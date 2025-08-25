"""
Dependency resolution for Gibson Framework modules.

Handles Python package dependencies and inter-module dependencies with
version constraint resolution and circular dependency detection.
"""

import asyncio
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Any
from packaging import version
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from loguru import logger

from gibson.core.module_management.models import (
    DependencyGraph,
    DependencyNode,
    DependencyEdge,
    DependencyConflict,
    DependencyResolutionResult
)
from gibson.core.module_management.exceptions import (
    DependencyError,
    CircularDependencyError,
    VersionConflictError
)


class DependencyResolver:
    """Resolves and manages module dependencies."""
    
    def __init__(self, pip_client=None):
        """
        Initialize dependency resolver.
        
        Args:
            pip_client: Optional PipClient for Python package management
        """
        self.pip_client = pip_client
        self._dependency_cache: Dict[str, DependencyNode] = {}
        self._resolution_cache: Dict[str, DependencyResolutionResult] = {}
    
    async def resolve_dependencies(
        self,
        module_name: str,
        dependencies: List[str],
        dev_dependencies: Optional[List[str]] = None,
        skip_python_packages: bool = False
    ) -> DependencyResolutionResult:
        """
        Resolve all dependencies for a module.
        
        Args:
            module_name: Name of the module
            dependencies: List of dependency specifications
            dev_dependencies: Optional development dependencies
            skip_python_packages: Whether to skip Python package resolution
            
        Returns:
            DependencyResolutionResult with resolution details
            
        Raises:
            CircularDependencyError: If circular dependencies detected
            VersionConflictError: If version conflicts cannot be resolved
        """
        cache_key = f"{module_name}:{':'.join(sorted(dependencies))}"
        if cache_key in self._resolution_cache:
            return self._resolution_cache[cache_key]
        
        try:
            # Build dependency graph
            graph = await self._build_dependency_graph(
                module_name,
                dependencies,
                dev_dependencies
            )
            
            # Check for circular dependencies
            cycles = self._detect_circular_dependencies(graph)
            if cycles:
                raise CircularDependencyError(
                    f"Circular dependencies detected: {' -> '.join(cycles[0])}"
                )
            
            # Resolve version conflicts
            conflicts = await self._find_version_conflicts(graph)
            if conflicts and not await self._resolve_conflicts(conflicts):
                raise VersionConflictError(
                    f"Cannot resolve version conflicts: {conflicts}"
                )
            
            # Get resolution order (topological sort)
            resolution_order = self._topological_sort(graph)
            
            # Separate Python packages from Gibson modules
            python_packages = []
            gibson_modules = []
            
            for dep in resolution_order:
                if dep.startswith("gibson-") or dep in self._get_known_gibson_modules():
                    gibson_modules.append(dep)
                else:
                    python_packages.append(dep)
            
            result = DependencyResolutionResult(
                success=True,
                graph=graph,
                resolution_order=resolution_order,
                python_packages=python_packages if not skip_python_packages else [],
                gibson_modules=gibson_modules,
                conflicts=conflicts,
                warnings=[]
            )
            
            self._resolution_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.error(f"Failed to resolve dependencies for {module_name}: {e}")
            return DependencyResolutionResult(
                success=False,
                graph=DependencyGraph(
                    root_module=module_name,
                    nodes={},
                    edges=[],
                    conflicts=[]
                ),
                resolution_order=[],
                python_packages=[],
                gibson_modules=[],
                conflicts=[],
                warnings=[],
                error=str(e)
            )
    
    async def _build_dependency_graph(
        self,
        root_module: str,
        dependencies: List[str],
        dev_dependencies: Optional[List[str]] = None
    ) -> DependencyGraph:
        """Build a dependency graph from dependency specifications."""
        nodes = {}
        edges = []
        queue = deque([(root_module, dependencies, False)])
        visited = set()
        
        # Add root node
        nodes[root_module] = DependencyNode(
            name=root_module,
            version_spec="*",
            resolved_version=None,
            is_dev=False,
            dependencies=dependencies
        )
        
        while queue:
            current, deps, is_dev = queue.popleft()
            
            if current in visited:
                continue
            visited.add(current)
            
            for dep_spec in deps:
                dep_name, version_spec = self._parse_dependency_spec(dep_spec)
                
                # Add node if not exists
                if dep_name not in nodes:
                    nodes[dep_name] = DependencyNode(
                        name=dep_name,
                        version_spec=version_spec,
                        resolved_version=None,
                        is_dev=is_dev,
                        dependencies=[]
                    )
                
                # Add edge
                edges.append(DependencyEdge(
                    source=current,
                    target=dep_name,
                    version_constraint=version_spec,
                    is_dev=is_dev
                ))
                
                # Queue for processing if it's a Gibson module
                if dep_name.startswith("gibson-") or dep_name in self._get_known_gibson_modules():
                    sub_deps = await self._get_module_dependencies(dep_name)
                    if sub_deps and dep_name not in visited:
                        queue.append((dep_name, sub_deps, is_dev))
        
        # Add dev dependencies
        if dev_dependencies:
            for dep_spec in dev_dependencies:
                dep_name, version_spec = self._parse_dependency_spec(dep_spec)
                
                if dep_name not in nodes:
                    nodes[dep_name] = DependencyNode(
                        name=dep_name,
                        version_spec=version_spec,
                        resolved_version=None,
                        is_dev=True,
                        dependencies=[]
                    )
                
                edges.append(DependencyEdge(
                    source=root_module,
                    target=dep_name,
                    version_constraint=version_spec,
                    is_dev=True
                ))
        
        return DependencyGraph(
            root_module=root_module,
            nodes=nodes,
            edges=edges,
            conflicts=[]
        )
    
    def _detect_circular_dependencies(self, graph: DependencyGraph) -> List[List[str]]:
        """
        Detect circular dependencies in the graph.
        
        Returns:
            List of cycles found (each cycle is a list of module names)
        """
        # Build adjacency list
        adj_list = defaultdict(list)
        for edge in graph.edges:
            adj_list[edge.source].append(edge.target)
        
        # Track visited nodes and recursion stack
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in adj_list[node]:
                if neighbor not in visited:
                    dfs(neighbor, path.copy())
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)
            
            rec_stack.remove(node)
        
        # Check from all nodes
        for node in graph.nodes:
            if node not in visited:
                dfs(node, [])
        
        return cycles
    
    async def _find_version_conflicts(self, graph: DependencyGraph) -> List[DependencyConflict]:
        """Find version conflicts in the dependency graph."""
        conflicts = []
        version_requirements = defaultdict(list)
        
        # Collect all version requirements for each package
        for edge in graph.edges:
            version_requirements[edge.target].append({
                'source': edge.source,
                'constraint': edge.version_constraint
            })
        
        # Check for conflicts
        for package, requirements in version_requirements.items():
            if len(requirements) <= 1:
                continue
            
            # Parse all constraints
            specifiers = []
            for req in requirements:
                try:
                    if req['constraint'] and req['constraint'] != '*':
                        specifiers.append((req['source'], SpecifierSet(req['constraint'])))
                except Exception as e:
                    logger.warning(f"Invalid version specifier: {req['constraint']}: {e}")
            
            # Check if constraints are compatible
            if specifiers and not self._are_specifiers_compatible(specifiers):
                conflict = DependencyConflict(
                    package=package,
                    requirements=[
                        f"{r['source']} requires {r['constraint']}"
                        for r in requirements
                    ],
                    resolution=None
                )
                conflicts.append(conflict)
        
        return conflicts
    
    def _are_specifiers_compatible(self, specifiers: List[Tuple[str, SpecifierSet]]) -> bool:
        """Check if version specifiers are compatible."""
        if not specifiers:
            return True
        
        # Try to find a version that satisfies all specifiers
        # This is a simplified check - real implementation would query available versions
        combined = SpecifierSet()
        try:
            for _, spec in specifiers:
                combined &= spec
            # If we can combine them without error, they're potentially compatible
            return True
        except Exception:
            return False
    
    async def _resolve_conflicts(self, conflicts: List[DependencyConflict]) -> bool:
        """
        Attempt to resolve version conflicts.
        
        Returns:
            True if all conflicts resolved, False otherwise
        """
        for conflict in conflicts:
            # Try to find a version that satisfies all requirements
            # This is a placeholder - real implementation would:
            # 1. Query available versions from registry
            # 2. Find compatible version
            # 3. Update conflict.resolution
            logger.warning(f"Version conflict for {conflict.package}: {conflict.requirements}")
            
            # For now, we'll use the latest specified version
            conflict.resolution = "Use latest compatible version"
        
        return True  # Optimistically assume we can resolve
    
    def _topological_sort(self, graph: DependencyGraph) -> List[str]:
        """
        Perform topological sort to get dependency resolution order.
        
        Returns:
            List of module names in resolution order
        """
        # Build adjacency list and in-degree count
        adj_list = defaultdict(list)
        in_degree = defaultdict(int)
        
        # Initialize all nodes
        for node in graph.nodes:
            in_degree[node] = 0
        
        # Build graph
        for edge in graph.edges:
            adj_list[edge.source].append(edge.target)
            in_degree[edge.target] += 1
        
        # Find nodes with no dependencies
        queue = deque([node for node in graph.nodes if in_degree[node] == 0])
        result = []
        
        while queue:
            node = queue.popleft()
            result.append(node)
            
            # Update in-degrees
            for neighbor in adj_list[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        # If result doesn't include all nodes, there's a cycle
        if len(result) != len(graph.nodes):
            # This shouldn't happen as we check for cycles earlier
            logger.error("Topological sort failed - cycle detected")
            return list(graph.nodes.keys())
        
        return result
    
    def _parse_dependency_spec(self, spec: str) -> Tuple[str, str]:
        """
        Parse a dependency specification.
        
        Args:
            spec: Dependency specification (e.g., "package>=1.0.0")
            
        Returns:
            Tuple of (package_name, version_spec)
        """
        try:
            req = Requirement(spec)
            return req.name, str(req.specifier) if req.specifier else "*"
        except Exception:
            # Simple parsing fallback
            if ">=" in spec:
                name, version = spec.split(">=", 1)
                return name.strip(), f">={version.strip()}"
            elif "==" in spec:
                name, version = spec.split("==", 1)
                return name.strip(), f"=={version.strip()}"
            elif ">" in spec:
                name, version = spec.split(">", 1)
                return name.strip(), f">{version.strip()}"
            elif "<" in spec:
                name, version = spec.split("<", 1)
                return name.strip(), f"<{version.strip()}"
            else:
                return spec.strip(), "*"
    
    async def _get_module_dependencies(self, module_name: str) -> List[str]:
        """Get dependencies for a Gibson module."""
        # This would query the module registry or database
        # For now, return empty list
        return []
    
    def _get_known_gibson_modules(self) -> Set[str]:
        """Get set of known Gibson module names."""
        # This would be populated from the module registry
        return {
            "gibson-prompts",
            "gibson-data",
            "gibson-model",
            "gibson-system",
            "gibson-output"
        }
    
    async def check_compatibility(
        self,
        module_name: str,
        target_version: str,
        current_dependencies: Dict[str, str]
    ) -> bool:
        """
        Check if a module version is compatible with current dependencies.
        
        Args:
            module_name: Module to check
            target_version: Version to check
            current_dependencies: Currently installed dependencies
            
        Returns:
            True if compatible, False otherwise
        """
        # Check if the target version satisfies all constraints
        for dep_name, dep_version in current_dependencies.items():
            if dep_name == module_name:
                continue
            
            # Would check if target_version satisfies constraints
            # For now, return True
            pass
        
        return True
    
    async def get_dependency_tree(
        self,
        module_name: str,
        max_depth: int = 10
    ) -> Dict[str, Any]:
        """
        Get a dependency tree for visualization.
        
        Args:
            module_name: Root module
            max_depth: Maximum tree depth
            
        Returns:
            Dictionary representing the dependency tree
        """
        tree = {
            "name": module_name,
            "version": "*",
            "dependencies": []
        }
        
        visited = set()
        
        async def build_tree(node: Dict, current_module: str, depth: int):
            if depth >= max_depth or current_module in visited:
                return
            
            visited.add(current_module)
            deps = await self._get_module_dependencies(current_module)
            
            for dep_spec in deps:
                dep_name, version_spec = self._parse_dependency_spec(dep_spec)
                child = {
                    "name": dep_name,
                    "version": version_spec,
                    "dependencies": []
                }
                node["dependencies"].append(child)
                
                if dep_name.startswith("gibson-") or dep_name in self._get_known_gibson_modules():
                    await build_tree(child, dep_name, depth + 1)
        
        await build_tree(tree, module_name, 0)
        return tree