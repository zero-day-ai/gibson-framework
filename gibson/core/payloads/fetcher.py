"""GitHub repository fetching for payload synchronization."""
import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import aiofiles
import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from gibson.models.payload import PayloadModel
from gibson.models.domain import AttackDomain
from .types import SyncResult


class PayloadFetcher:
    """Fetches payloads from repositories.
    
    This is a legacy class that may be deprecated in favor of GitSync.
    Currently provides basic payload fetching functionality.
    """

    def __init__(self):
        """Initialize payload fetcher."""
        self._session: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._close_session()

    async def _create_session(self) ->None:
        """Create authenticated HTTP session."""
        # No authentication for now - GitSync handles auth
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Gibson-Framework/1.0.0'
        }
        self._session = httpx.AsyncClient(headers=headers, timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=10,
            max_connections=20, keepalive_expiry=30.0))

    async def _close_session(self) ->None:
        """Close HTTP session."""
        if self._session:
            await self._session.aclose()
            self._session = None

    async def sync_repository(self, repository: str, branch: str='main',
        target_domains: Optional[List[AttackDomain]]=None, force_update:
        bool=False) ->SyncResult:
        """Synchronize payloads from GitHub repository.
        
        Args:
            repository: Repository in format 'owner/repo'
            branch: Git branch to sync from
            target_domains: Specific domains to sync (None for all)
            force_update: Force update even if no changes
            
        Returns:
            SyncResult with operation details
        """
        start_time = datetime.utcnow()
        result = SyncResult(success=False, repository=repository, branch=
            branch, sync_timestamp=start_time)
        try:
            logger.info(f'Starting sync from {repository}:{branch}')
            if not self._session:
                await self._create_session()
            repo_info = await self._get_repository_info(repository)
            if not repo_info:
                result.errors.append(
                    f'Repository {repository} not found or inaccessible')
                return result
            latest_commit = await self._get_latest_commit(repository, branch)
            if not latest_commit:
                result.errors.append(
                    f'Branch {branch} not found in {repository}')
                return result
            result.last_commit = latest_commit['sha']
            tree_items = await self._get_repository_tree(repository,
                latest_commit['sha'])
            if not tree_items:
                result.errors.append('Failed to retrieve repository contents')
                return result
            payload_files = self._filter_payload_files(tree_items,
                target_domains)
            result.fetched_count = len(payload_files)
            if not payload_files:
                logger.info(f'No payload files found in {repository}')
                result.success = True
                return result
            download_size = 0
            for file_info in payload_files:
                try:
                    payload_data = await self._download_file_content(repository
                        , file_info)
                    if payload_data:
                        download_size += len(payload_data)
                        payload = self._parse_payload_file(file_info,
                            payload_data, repository)
                        if payload:
                            result.new_payloads.append(payload.name)
                            result.imported_count += 1
                        else:
                            result.errors.append(
                                f"Failed to parse {file_info['path']}")
                            result.error_count += 1
                except Exception as e:
                    logger.error(f"Failed to process {file_info['path']}: {e}")
                    result.errors.append(
                        f"Error processing {file_info['path']}: {str(e)}")
                    result.error_count += 1
            result.download_size_bytes = download_size
            result.success = (result.imported_count > 0 or result.
                error_count == 0)
            end_time = datetime.utcnow()
            result.sync_duration_ms = int((end_time - start_time).
                total_seconds() * 1000)
            logger.info(
                f'Sync completed: {result.imported_count} imported, {result.error_count} errors in {result.sync_duration_ms}ms'
                )
            return result
        except Exception as e:
            logger.error(f'Repository sync failed: {e}')
            result.errors.append(f'Sync failed: {str(e)}')
            return result

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1,
        min=4, max=10), reraise=True)
    async def _get_repository_info(self, repository: str) ->Optional[Dict[
        str, Any]]:
        """Get repository information from GitHub API.
        
        Args:
            repository: Repository in format 'owner/repo'
            
        Returns:
            Repository information or None if not found
        """
        try:
            url = f'https://api.github.com/repos/{repository}'
            response = await self._session.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.warning(f'Repository not found: {repository}')
                return None
            elif response.status_code == 403:
                logger.error(f'Access denied to repository: {repository}')
                return None
            else:
                response.raise_for_status()
        except Exception as e:
            logger.error(f'Failed to get repository info for {repository}: {e}'
                )
            raise

    async def _get_latest_commit(self, repository: str, branch: str
        ) ->Optional[Dict[str, Any]]:
        """Get latest commit for branch.
        
        Args:
            repository: Repository in format 'owner/repo'
            branch: Branch name
            
        Returns:
            Commit information or None if not found
        """
        try:
            url = f'https://api.github.com/repos/{repository}/commits/{branch}'
            response = await self._session.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.warning(f'Branch {branch} not found in {repository}')
                return None
            else:
                response.raise_for_status()
        except Exception as e:
            logger.error(
                f'Failed to get latest commit for {repository}:{branch}: {e}')
            return None

    async def _get_repository_tree(self, repository: str, commit_sha: str,
        recursive: bool=True) ->List[Dict[str, Any]]:
        """Get repository file tree.
        
        Args:
            repository: Repository in format 'owner/repo'
            commit_sha: Commit SHA to get tree for
            recursive: Whether to get recursive tree
            
        Returns:
            List of file/directory information
        """
        try:
            url = (
                f'https://api.github.com/repos/{repository}/git/trees/{commit_sha}'
                )
            params = {'recursive': '1'} if recursive else {}
            response = await self._session.get(url, params=params)
            response.raise_for_status()
            tree_data = response.json()
            return tree_data.get('tree', [])
        except Exception as e:
            logger.error(f'Failed to get repository tree for {repository}: {e}'
                )
            return []

    def _filter_payload_files(self, tree_items: List[Dict[str, Any]],
        target_domains: Optional[List[AttackDomain]]=None) ->List[Dict[str,
        Any]]:
        """Filter tree items to payload files.
        
        Args:
            tree_items: Repository tree items
            target_domains: Domains to include (None for all)
            
        Returns:
            Filtered list of payload files
        """
        payload_files = []
        payload_extensions = {'.txt', '.json', '.yaml', '.yml', '.md'}
        domain_paths = {AttackDomain.PROMPT: ['prompts', 'prompt',
            'injection'], AttackDomain.DATA: ['data', 'datasets',
            'poisoning'], AttackDomain.MODEL: ['model', 'models',
            'adversarial'], AttackDomain.SYSTEM: ['system', 'enum',
            'enumeration'], AttackDomain.OUTPUT: ['output', 'response',
            'format']}
        for item in tree_items:
            if item.get('type') != 'blob':
                continue
            path = Path(item['path'])
            if path.suffix.lower() not in payload_extensions:
                continue
            item_domain = self._determine_domain_from_path(path, domain_paths)
            if target_domains and item_domain not in target_domains:
                continue
            if any(skip in path.name.lower() for skip in ['readme',
                'license', 'changelog']):
                continue
            payload_files.append({**item, 'domain': item_domain,
                'attack_type': self._determine_attack_type_from_path(path)})
        logger.debug(
            f'Filtered {len(payload_files)} payload files from {len(tree_items)} items'
            )
        return payload_files

    def _determine_domain_from_path(self, path: Path, domain_paths: Dict[
        AttackDomain, List[str]]) ->Optional[AttackDomain]:
        """Determine payload domain from file path.
        
        Args:
            path: File path
            domain_paths: Mapping of domains to path patterns
            
        Returns:
            Detected domain or None
        """
        path_str = str(path).lower()
        for domain, patterns in domain_paths.items():
            if any(pattern in path_str for pattern in patterns):
                return domain
        return AttackDomain.PROMPT

    def _determine_attack_type_from_path(self, path: Path) ->str:
        """Determine attack type from file path.
        
        Args:
            path: File path
            
        Returns:
            Attack type name
        """
        path_str = str(path).lower()
        attack_patterns = {'injection': ['inject', 'sqli', 'xss', 'command'
            ], 'jailbreak': ['jailbreak', 'bypass', 'escape'], 'poisoning':
            ['poison', 'backdoor', 'trojan'], 'evasion': ['evasion',
            'adversarial', 'dodge'], 'enumeration': ['enum', 'scan',
            'discover'], 'extraction': ['extract', 'leak', 'dump']}
        for attack_type, patterns in attack_patterns.items():
            if any(pattern in path_str for pattern in patterns):
                return attack_type
        parts = path.parts
        if len(parts) > 1:
            return parts[-2]
        return 'generic'

    async def _download_file_content(self, repository: str, file_info: Dict
        [str, Any]) ->Optional[str]:
        """Download file content from GitHub.
        
        Args:
            repository: Repository in format 'owner/repo'
            file_info: File information from tree
            
        Returns:
            File content as string or None if failed
        """
        try:
            if file_info.get('size', 0) < 1024 * 1024:
                url = (
                    f"https://api.github.com/repos/{repository}/contents/{file_info['path']}"
                    )
                response = await self._session.get(url)
                response.raise_for_status()
                content_data = response.json()
                if content_data.get('encoding') == 'base64':
                    import base64
                    return base64.b64decode(content_data['content']).decode(
                        'utf-8')
            url = (
                f"https://api.github.com/repos/{repository}/git/blobs/{file_info['sha']}"
                )
            response = await self._session.get(url)
            response.raise_for_status()
            blob_data = response.json()
            if blob_data.get('encoding') == 'base64':
                import base64
                return base64.b64decode(blob_data['content']).decode('utf-8')
            return None
        except Exception as e:
            logger.error(f"Failed to download {file_info['path']}: {e}")
            return None

    def _parse_payload_file(self, file_info: Dict[str, Any], content: str,
        repository: str) ->Optional[PayloadModel]:
        """Parse file content into Payload object.
        
        Args:
            file_info: File information
            content: File content
            repository: Source repository
            
        Returns:
            Parsed Payload or None if failed
        """
        try:
            path = Path(file_info['path'])
            if path.suffix.lower() == '.json':
                return self._parse_json_payload(file_info, content, repository)
            elif path.suffix.lower() in ['.yaml', '.yml']:
                return self._parse_yaml_payload(file_info, content, repository)
            else:
                return self._parse_text_payload(file_info, content, repository)
        except Exception as e:
            logger.error(f"Failed to parse payload {file_info['path']}: {e}")
            return None

    def _parse_json_payload(self, file_info: Dict[str, Any], content: str,
        repository: str) ->Optional[PayloadModel]:
        """Parse JSON payload file."""
        try:
            data = json.loads(content)
            if isinstance(data, dict) and 'payload' in data:
                return PayloadModel.from_minimal(name=data.get('name', Path(file_info['path']
                    ).stem), content=data['payload'], domain=file_info.get(
                    'domain', AttackDomain.PROMPT), attack_type=data.get(
                    'attack_type', file_info.get('attack_type', 'generic')),
                    attack_vector=data.get('attack_vector', 'injection'),
                    description=data.get('description'), severity=data.get(
                    'severity', 'medium'), tags=data.get('tags', []),
                    source_repo=repository, source_path=file_info['path'])
            elif isinstance(data, list):
                if data and isinstance(data[0], str):
                    return PayloadModel.from_minimal(name=Path(file_info['path']).stem,
                        content=data[0], domain=file_info.get('domain',
                        AttackDomain.PROMPT), attack_type=file_info.get(
                        'attack_type', 'generic'), attack_vector=
                        'injection', source_repo=repository, source_path=
                        file_info['path'])
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_info['path']}: {e}")
            return None

    def _parse_yaml_payload(self, file_info: Dict[str, Any], content: str,
        repository: str) ->Optional[PayloadModel]:
        """Parse YAML payload file."""
        try:
            import yaml
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'payload' in data:
                return PayloadModel.from_minimal(name=data.get('name', Path(file_info['path']
                    ).stem), content=data['payload'], domain=file_info.get(
                    'domain', AttackDomain.PROMPT), attack_type=data.get(
                    'attack_type', file_info.get('attack_type', 'generic')),
                    attack_vector=data.get('attack_vector', 'injection'),
                    description=data.get('description'), severity=data.get(
                    'severity', 'medium'), tags=data.get('tags', []),
                    source_repo=repository, source_path=file_info['path'])
            return None
        except Exception as e:
            logger.error(f"Failed to parse YAML {file_info['path']}: {e}")
            return None

    def _parse_text_payload(self, file_info: Dict[str, Any], content: str,
        repository: str) ->Optional[PayloadModel]:
        """Parse plain text payload file."""
        try:
            lines = content.strip().split('\n')
            metadata = {}
            payload_lines = []
            in_metadata = True
            for line in lines:
                if in_metadata and line.startswith('#'):
                    if ':' in line:
                        key, value = line[1:].split(':', 1)
                        metadata[key.strip().lower()] = value.strip()
                    continue
                else:
                    in_metadata = False
                    payload_lines.append(line)
            payload_content = '\n'.join(payload_lines).strip()
            if not payload_content:
                payload_content = content.strip()
            return PayloadModel.from_minimal(name=metadata.get('name', Path(file_info['path']
                ).stem), content=payload_content, domain=file_info.get(
                'domain', AttackDomain.PROMPT), attack_type=metadata.get(
                'attack_type', file_info.get('attack_type', 'generic')),
                attack_vector=metadata.get('attack_vector', 'injection'),
                description=metadata.get('description'), severity=metadata.
                get('severity', 'medium'), tags=metadata.get('tags', '').
                split(',') if metadata.get('tags') else [], source_repo=
                repository, source_path=file_info['path'])
        except Exception as e:
            logger.error(
                f"Failed to parse text payload {file_info['path']}: {e}")
            return None

    async def list_repository_payloads(self, repository: str, branch: str=
        'main') ->List[Dict[str, Any]]:
        """List available payloads in repository without downloading.
        
        Args:
            repository: Repository in format 'owner/repo'
            branch: Git branch to check
            
        Returns:
            List of payload file information
        """
        try:
            if not self._session:
                await self._create_session()
            latest_commit = await self._get_latest_commit(repository, branch)
            if not latest_commit:
                return []
            tree_items = await self._get_repository_tree(repository,
                latest_commit['sha'])
            return self._filter_payload_files(tree_items)
        except Exception as e:
            logger.error(f'Failed to list payloads in {repository}: {e}')
            return []

    async def check_repository_access(self, repository: str) ->Tuple[bool,
        Optional[str]]:
        """Check if repository is accessible.
        
        Args:
            repository: Repository in format 'owner/repo'
            
        Returns:
            Tuple of (accessible, error_message)
        """
        try:
            if not self._session:
                await self._create_session()
            repo_info = await self._get_repository_info(repository)
            if repo_info:
                return True, None
            else:
                return False, 'Repository not found or access denied'
        except Exception as e:
            return False, str(e)
