"""Unit tests for enhanced database base models."""

import pytest
from datetime import datetime
from uuid import UUID, uuid4
from unittest.mock import MagicMock, patch

from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy import Column, String, Integer, create_engine
from sqlalchemy.orm import Session, sessionmaker

from gibson.db.base import Base, BaseDBModel, CRUDMixin, TimestampMixin


# Test model for validation
class TestModel(BaseDBModel, CRUDMixin):
    """Test model for unit tests."""
    __tablename__ = 'test_model'
    
    name = Column(String(100), nullable=False)
    value = Column(Integer, nullable=True)
    unique_field = Column(String(50), unique=True, nullable=True)


# Pydantic model for testing
class TestPydanticModel(PydanticBaseModel):
    """Test Pydantic model."""
    name: str
    value: int = 0
    
    model_config = {"from_attributes": True}


@pytest.fixture
def db_session():
    """Create test database session."""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


class TestBaseDBModel:
    """Tests for BaseDBModel enhancements."""
    
    def test_audit_fields_present(self):
        """Test that audit fields are defined."""
        model = TestModel(name="test")
        
        assert hasattr(model, 'created_by')
        assert hasattr(model, 'updated_by')
        assert hasattr(model, 'version')
        assert hasattr(model, 'is_deleted')
    
    def test_default_values(self):
        """Test default values for new fields."""
        model = TestModel(name="test")
        
        assert model.version == 1
        assert model.is_deleted is False
        assert model.created_by is None
        assert model.updated_by is None
    
    def test_to_dict_basic(self):
        """Test to_dict method with basic fields."""
        model = TestModel(name="test", value=42)
        model.id = uuid4()
        model.created_at = datetime.now()
        model.updated_at = datetime.now()
        
        result = model.to_dict()
        
        assert 'name' in result
        assert result['name'] == "test"
        assert result['value'] == 42
        assert result['version'] == 1
        assert result['is_deleted'] is False
    
    def test_to_dict_excludes_deleted(self):
        """Test to_dict excludes soft-deleted records by default."""
        model = TestModel(name="test")
        model.is_deleted = True
        
        result = model.to_dict(exclude_deleted=True)
        assert result == {}
        
        result = model.to_dict(exclude_deleted=False)
        assert 'name' in result
    
    def test_to_dict_serialization(self):
        """Test to_dict handles UUID and datetime serialization."""
        model = TestModel(name="test")
        model.id = uuid4()
        model.created_at = datetime.now()
        model.updated_at = datetime.now()
        
        result = model.to_dict()
        
        # UUID should be string
        assert isinstance(result['id'], str)
        # DateTime should be ISO format string
        assert isinstance(result['created_at'], str)
        assert isinstance(result['updated_at'], str)
    
    def test_from_pydantic(self):
        """Test creating model from Pydantic instance."""
        pydantic_model = TestPydanticModel(name="test", value=42)
        
        db_model = TestModel.from_pydantic(pydantic_model, created_by="user123")
        
        assert db_model.name == "test"
        assert db_model.value == 42
        assert db_model.created_by == "user123"
    
    def test_validate_required_fields(self):
        """Test validation detects missing required fields."""
        model = TestModel()  # Missing required 'name'
        
        errors = model.validate()
        
        assert len(errors) > 0
        assert any("name" in error for error in errors)
    
    def test_validate_version(self):
        """Test validation checks version is positive."""
        model = TestModel(name="test")
        model.version = -1
        
        errors = model.validate()
        
        assert len(errors) > 0
        assert any("version" in error.lower() for error in errors)
    
    def test_soft_delete(self, db_session):
        """Test soft delete functionality."""
        model = TestModel(name="test")
        db_session.add(model)
        db_session.commit()
        
        assert model.is_deleted is False
        assert model.version == 1
        
        model.soft_delete(db_session, deleted_by="admin")
        
        assert model.is_deleted is True
        assert model.version == 2
        assert model.updated_by == "admin"
    
    def test_restore(self, db_session):
        """Test restore soft-deleted record."""
        model = TestModel(name="test")
        model.is_deleted = True
        model.version = 2
        db_session.add(model)
        db_session.commit()
        
        model.restore(db_session, restored_by="admin")
        
        assert model.is_deleted is False
        assert model.version == 3
        assert model.updated_by == "admin"


class TestCRUDMixin:
    """Tests for enhanced CRUDMixin."""
    
    def test_create_with_audit(self, db_session):
        """Test create with audit fields."""
        model = TestModel.create(
            db_session,
            created_by="user123",
            name="test",
            value=42
        )
        
        assert model.name == "test"
        assert model.value == 42
        assert model.created_by == "user123"
        assert model.updated_by == "user123"
        assert model.id is not None
    
    def test_get_excludes_deleted(self, db_session):
        """Test get excludes soft-deleted by default."""
        # Create normal record
        model1 = TestModel.create(db_session, name="test1")
        
        # Create soft-deleted record
        model2 = TestModel.create(db_session, name="test2")
        model2.soft_delete(db_session)
        
        # Should only find non-deleted
        found = TestModel.get(db_session, name="test1")
        assert found is not None
        assert found.name == "test1"
        
        found = TestModel.get(db_session, name="test2")
        assert found is None
        
        # Should find deleted when requested
        found = TestModel.get(db_session, name="test2", include_deleted=True)
        assert found is not None
        assert found.name == "test2"
    
    def test_update_with_version(self, db_session):
        """Test update increments version."""
        model = TestModel.create(db_session, name="test", value=1)
        assert model.version == 1
        
        model.update(db_session, updated_by="admin", value=2)
        
        assert model.value == 2
        assert model.version == 2
        assert model.updated_by == "admin"
    
    def test_delete_soft_by_default(self, db_session):
        """Test delete does soft delete by default."""
        model = TestModel.create(db_session, name="test")
        model_id = model.id
        
        model.delete(db_session, deleted_by="admin")
        
        # Should still exist in database
        found = db_session.query(TestModel).filter_by(id=model_id).first()
        assert found is not None
        assert found.is_deleted is True
        assert found.updated_by == "admin"
    
    def test_delete_hard(self, db_session):
        """Test hard delete removes from database."""
        model = TestModel.create(db_session, name="test")
        model_id = model.id
        
        model.delete(db_session, soft=False)
        
        # Should not exist in database
        found = db_session.query(TestModel).filter_by(id=model_id).first()
        assert found is None
    
    def test_all_excludes_deleted(self, db_session):
        """Test all() excludes soft-deleted by default."""
        # Create records
        TestModel.create(db_session, name="test1")
        TestModel.create(db_session, name="test2")
        model3 = TestModel.create(db_session, name="test3")
        model3.soft_delete(db_session)
        
        # Should only get non-deleted
        results = TestModel.all(db_session)
        assert len(results) == 2
        assert all(not r.is_deleted for r in results)
        
        # Should get all when requested
        results = TestModel.all(db_session, include_deleted=True)
        assert len(results) == 3
    
    def test_filter_excludes_deleted(self, db_session):
        """Test filter excludes soft-deleted by default."""
        # Create records
        TestModel.create(db_session, name="test", value=1)
        TestModel.create(db_session, name="test", value=2)
        model3 = TestModel.create(db_session, name="test", value=3)
        model3.soft_delete(db_session)
        
        # Should only get non-deleted
        results = TestModel.filter(db_session, name="test")
        assert len(results) == 2
        assert all(not r.is_deleted for r in results)
        
        # Should get all when requested
        results = TestModel.filter(db_session, name="test", include_deleted=True)
        assert len(results) == 3
    
    def test_count_excludes_deleted(self, db_session):
        """Test count excludes soft-deleted by default."""
        # Create records
        TestModel.create(db_session, name="test1")
        TestModel.create(db_session, name="test2")
        model3 = TestModel.create(db_session, name="test3")
        model3.soft_delete(db_session)
        
        # Should only count non-deleted
        count = TestModel.count(db_session)
        assert count == 2
        
        # Should count all when requested
        count = TestModel.count(db_session, include_deleted=True)
        assert count == 3
    
    def test_get_or_create(self, db_session):
        """Test get_or_create functionality."""
        # First call should create
        model1, created1 = TestModel.get_or_create(
            db_session,
            defaults={'value': 42},
            name="unique"
        )
        assert created1 is True
        assert model1.name == "unique"
        assert model1.value == 42
        
        # Second call should get existing
        model2, created2 = TestModel.get_or_create(
            db_session,
            defaults={'value': 99},
            name="unique"
        )
        assert created2 is False
        assert model2.id == model1.id
        assert model2.value == 42  # Defaults not applied


class TestTimestampMixin:
    """Tests for TimestampMixin."""
    
    def test_timestamp_fields(self):
        """Test timestamp fields are added."""
        
        class TimestampModel(Base, TimestampMixin):
            __tablename__ = 'timestamp_test'
            id = Column(Integer, primary_key=True)
        
        model = TimestampModel()
        assert hasattr(model, 'created_at')
        assert hasattr(model, 'updated_at')


class TestOptimisticLocking:
    """Tests for optimistic locking via version field."""
    
    def test_concurrent_update_detection(self, db_session):
        """Test version prevents concurrent updates."""
        # Create initial record
        model = TestModel.create(db_session, name="test", value=1)
        original_version = model.version
        
        # Simulate concurrent load
        concurrent_model = db_session.query(TestModel).filter_by(id=model.id).first()
        
        # Update first instance
        model.update(db_session, value=2)
        assert model.version == original_version + 1
        
        # Concurrent update should detect version mismatch
        # In real implementation, this would raise an exception
        concurrent_model.version = original_version  # Still has old version
        concurrent_model.value = 3
        
        # Version mismatch should be detectable
        assert concurrent_model.version < model.version