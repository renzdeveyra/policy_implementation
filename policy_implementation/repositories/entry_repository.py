"""
EntryRepository interface and implementations for the policy implementation system.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

class EntryRepository(ABC):
    """Abstract repository for blackboard entries"""
    
    @abstractmethod
    def add(self, entry: BlackboardEntry) -> Tuple[str, bool]:
        """
        Add an entry to the repository
        
        Args:
            entry: Entry to add
            
        Returns:
            Tuple[str, bool]: (entry_id, is_new) where is_new is True if a new entry was added
        """
        pass
    
    @abstractmethod
    def update(self, entry_id: str, **kwargs) -> bool:
        """
        Update an entry in the repository
        
        Args:
            entry_id: ID of the entry to update
            **kwargs: Attributes to update
            
        Returns:
            bool: True if the entry was updated
        """
        pass
    
    @abstractmethod
    def get(self, entry_id: str) -> Optional[BlackboardEntry]:
        """
        Get an entry by ID
        
        Args:
            entry_id: ID of the entry to get
            
        Returns:
            BlackboardEntry or None: The entry if found, None otherwise
        """
        pass
    
    @abstractmethod
    def query(self, **criteria) -> List[BlackboardEntry]:
        """
        Query entries based on criteria
        
        Args:
            **criteria: Criteria to filter by
            
        Returns:
            List[BlackboardEntry]: List of entries matching the criteria
        """
        pass
    
    @abstractmethod
    def delete(self, entry_id: str) -> bool:
        """
        Delete an entry from the repository
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            bool: True if the entry was deleted
        """
        pass
    
    @abstractmethod
    def get_all(self) -> List[BlackboardEntry]:
        """
        Get all entries in the repository
        
        Returns:
            List[BlackboardEntry]: List of all entries
        """
        pass

class InMemoryEntryRepository(EntryRepository):
    """In-memory implementation of the entry repository"""
    
    def __init__(self):
        """Initialize the repository"""
        self.entries = {}  # Dictionary of entry_id -> BlackboardEntry
        self.content_hash_map = {}  # Dictionary of content hash -> entry_id for deduplication
    
    def add(self, entry: BlackboardEntry) -> Tuple[str, bool]:
        """
        Add an entry to the repository
        
        Args:
            entry: Entry to add
            
        Returns:
            Tuple[str, bool]: (entry_id, is_new) where is_new is True if a new entry was added
        """
        # Deduplication logic
        dedup_key = self._create_deduplication_key(entry)
        
        # Check for duplicates
        if dedup_key in self.content_hash_map:
            existing_id = self.content_hash_map[dedup_key]
            existing_entry = self.entries.get(existing_id)
            
            if existing_entry and existing_entry.confidence < entry.confidence:
                # Replace with higher confidence entry
                self.entries[entry.entry_id] = entry
                self.content_hash_map[dedup_key] = entry.entry_id
                return entry.entry_id, True  # Added, replaced existing
            else:
                return existing_id, False  # Not added, duplicate exists
        
        # Add new entry
        self.entries[entry.entry_id] = entry
        self.content_hash_map[dedup_key] = entry.entry_id
        return entry.entry_id, True  # Added, new entry
    
    def update(self, entry_id: str, **kwargs) -> bool:
        """
        Update an entry in the repository
        
        Args:
            entry_id: ID of the entry to update
            **kwargs: Attributes to update
            
        Returns:
            bool: True if the entry was updated
        """
        if entry_id not in self.entries:
            return False
        
        entry = self.entries[entry_id]
        return entry.update(**kwargs)
    
    def get(self, entry_id: str) -> Optional[BlackboardEntry]:
        """
        Get an entry by ID
        
        Args:
            entry_id: ID of the entry to get
            
        Returns:
            BlackboardEntry or None: The entry if found, None otherwise
        """
        return self.entries.get(entry_id)
    
    def query(self, **criteria) -> List[BlackboardEntry]:
        """
        Query entries based on criteria
        
        Args:
            **criteria: Criteria to filter by
            
        Returns:
            List[BlackboardEntry]: List of entries matching the criteria
        """
        result = list(self.entries.values())
        
        for key, value in criteria.items():
            if key == 'entry_type':
                result = [entry for entry in result if entry.entry_type == value]
            elif key == 'status':
                result = [entry for entry in result if entry.status == value]
            elif key == 'source':
                result = [entry for entry in result if entry.source == value]
            elif key == 'rule_id':
                result = [entry for entry in result if entry.rule_id == value]
            elif key == 'related_to':
                result = [entry for entry in result if value in entry.related_entries]
            # Add more criteria as needed
        
        return result
    
    def delete(self, entry_id: str) -> bool:
        """
        Delete an entry from the repository
        
        Args:
            entry_id: ID of the entry to delete
            
        Returns:
            bool: True if the entry was deleted
        """
        if entry_id in self.entries:
            entry = self.entries[entry_id]
            dedup_key = self._create_deduplication_key(entry)
            
            if dedup_key in self.content_hash_map:
                del self.content_hash_map[dedup_key]
            
            del self.entries[entry_id]
            return True
        
        return False
    
    def get_all(self) -> List[BlackboardEntry]:
        """
        Get all entries in the repository
        
        Returns:
            List[BlackboardEntry]: List of all entries
        """
        return list(self.entries.values())
    
    def _create_deduplication_key(self, entry: BlackboardEntry) -> str:
        """
        Create a key for deduplication
        
        Args:
            entry: Entry to create a key for
            
        Returns:
            str: Deduplication key
        """
        # Use type, normalized content, and source for deduplication
        content_normalized = ' '.join(entry.content.lower().split())
        source_str = entry.source.name if entry.source else "None"
        
        # For certain entry types, also consider related entries
        if entry.entry_type in [EntryType.SOLUTION, EntryType.DECISION]:
            related_str = ','.join(sorted(entry.related_entries))
            return f"{entry.entry_type.name}:{content_normalized}:{source_str}:{related_str}"
        
        return f"{entry.entry_type.name}:{content_normalized}:{source_str}"
