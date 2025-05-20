"""
BlackboardEntry class for the policy implementation system.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

class BlackboardEntry:
    """Represents an entry on the blackboard"""
    
    def __init__(self, 
                 entry_id: str, 
                 entry_type: EntryType, 
                 content: str, 
                 source: Optional[ExpertRole] = None, 
                 rule_id: Optional[str] = None, 
                 status: EntryStatus = EntryStatus.NEW, 
                 confidence: float = 1.0, 
                 related_entries: Optional[List[str]] = None, 
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize a blackboard entry
        
        Args:
            entry_id: Unique identifier for the entry
            entry_type: Type of entry (issue, solution, etc.)
            content: Text content of the entry
            source: Expert role that created the entry
            rule_id: ID of the rule that created the entry (if any)
            status: Current status of the entry
            confidence: Confidence score (0.0 to 1.0)
            related_entries: List of related entry IDs
            metadata: Additional metadata for the entry
        """
        self.entry_id = entry_id
        self.entry_type = entry_type
        self.content = content
        self.source = source
        self.rule_id = rule_id
        self.status = status
        self.confidence = confidence
        self.related_entries = related_entries or []
        self.metadata = metadata or {}
        self.created_at = datetime.now()
        self.updated_at = self.created_at
    
    def update(self, **kwargs) -> bool:
        """
        Update entry attributes
        
        Args:
            **kwargs: Attributes to update
            
        Returns:
            bool: True if any attributes were updated
        """
        updated = False
        
        for key, value in kwargs.items():
            if hasattr(self, key) and key != 'entry_id':
                setattr(self, key, value)
                updated = True
        
        if updated:
            self.updated_at = datetime.now()
            
        return updated
    
    def __str__(self) -> str:
        """String representation of the entry"""
        return f"{self.entry_type.name}: {self.content} (Status: {self.status.name})"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization"""
        return {
            'entry_id': self.entry_id,
            'entry_type': self.entry_type.name,
            'content': self.content,
            'source': self.source.name if self.source else None,
            'rule_id': self.rule_id,
            'status': self.status.name,
            'confidence': self.confidence,
            'related_entries': self.related_entries,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
