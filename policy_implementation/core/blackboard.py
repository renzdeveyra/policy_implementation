"""
Blackboard interface and implementation for the policy implementation system.
"""
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

logger = logging.getLogger(__name__)

class BlackboardInterface(ABC):
    """Interface defining how knowledge sources interact with the blackboard"""
    
    @abstractmethod
    def add_entry(self, entry: BlackboardEntry) -> str:
        """Add a new entry to the blackboard"""
        pass
    
    @abstractmethod
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """Update an existing entry"""
        pass
    
    @abstractmethod
    def get_entry(self, entry_id: str) -> Optional[BlackboardEntry]:
        """Get an entry by its ID"""
        pass
    
    @abstractmethod
    def get_entries_by_type(self, entry_type: EntryType) -> List[BlackboardEntry]:
        """Get all entries of a specific type"""
        pass
    
    @abstractmethod
    def get_entries_by_status(self, status: EntryStatus) -> List[BlackboardEntry]:
        """Get all entries with a specific status"""
        pass
    
    @abstractmethod
    def get_entries_by_source(self, source: ExpertRole) -> List[BlackboardEntry]:
        """Get all entries from a specific source"""
        pass
    
    @abstractmethod
    def query_entries(self, **kwargs) -> List[BlackboardEntry]:
        """Query entries based on multiple criteria"""
        pass
    
    @abstractmethod
    def register_observer(self, observer) -> None:
        """Register an observer to be notified of blackboard changes"""
        pass
    
    @abstractmethod
    def notify_observers(self, event_type: str, data: Any) -> None:
        """Notify all observers of a change"""
        pass

class Blackboard(BlackboardInterface):
    """Central blackboard that holds all facts and partial solutions"""
    
    def __init__(self, repository=None):
        """
        Initialize the blackboard
        
        Args:
            repository: Optional repository for storing entries
        """
        self.entries = {}  # Dictionary of entry_id -> BlackboardEntry
        self.history = []  # List of tuples (timestamp, action, details)
        self.content_hash_map = {}  # Dictionary of content hash -> entry_id for deduplication
        self.observers = []  # List of observers to notify of changes
        self.repository = repository  # Optional repository for storing entries
    
    def add_entry(self, entry: BlackboardEntry) -> str:
        """
        Add a new entry to the blackboard, with deduplication
        
        Args:
            entry: The entry to add
            
        Returns:
            str: The ID of the added entry
        """
        # Create a hash for deduplication based on type, content, and source
        dedup_key = self._create_deduplication_key(entry)
        
        # Check if we already have a similar entry
        if dedup_key in self.content_hash_map:
            existing_entry_id = self.content_hash_map[dedup_key]
            existing_entry = self.entries.get(existing_entry_id)
            
            if existing_entry:
                # If the existing entry has lower confidence, replace it
                if existing_entry.confidence < entry.confidence:
                    self.entries[entry.entry_id] = entry
                    self.content_hash_map[dedup_key] = entry.entry_id
                    self.log_action("REPLACE_ENTRY", f"Replaced similar entry {existing_entry_id} with higher confidence entry {entry.entry_id}")
                    
                    # Update the status of the old entry to rejected
                    existing_entry.status = EntryStatus.REJECTED
                    existing_entry.metadata["rejected_reason"] = "Replaced by higher confidence entry"
                    existing_entry.metadata["replaced_by"] = entry.entry_id
                    
                    # Notify observers
                    self.notify_observers("entry_replaced", {
                        "new_entry": entry,
                        "old_entry": existing_entry
                    })
                    
                    return entry.entry_id
                else:
                    # Log that we're skipping a duplicate entry
                    self.log_action("SKIP_DUPLICATE", f"Skipped duplicate entry similar to {existing_entry_id}")
                    return existing_entry_id
        
        # If no duplicate found, add the new entry
        self.entries[entry.entry_id] = entry
        self.content_hash_map[dedup_key] = entry.entry_id
        self.log_action("ADD_ENTRY", f"Added entry {entry.entry_id} of type {entry.entry_type.name}")
        
        # Notify observers
        self.notify_observers("entry_added", entry)
        
        return entry.entry_id
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """
        Update an existing entry
        
        Args:
            entry_id: ID of the entry to update
            **kwargs: Attributes to update
            
        Returns:
            bool: True if the entry was updated
        """
        entry = self.get_entry(entry_id)
        if not entry:
            return False
        
        # Save old state for observers
        old_state = entry.to_dict()
        
        # Update the entry
        updated = entry.update(**kwargs)
        
        if updated:
            self.log_action("UPDATE_ENTRY", f"Updated entry {entry_id}")
            
            # Notify observers
            self.notify_observers("entry_updated", {
                "entry": entry,
                "old_state": old_state
            })
        
        return updated
    
    def get_entry(self, entry_id: str) -> Optional[BlackboardEntry]:
        """
        Get an entry by its ID
        
        Args:
            entry_id: ID of the entry to get
            
        Returns:
            BlackboardEntry or None: The entry if found, None otherwise
        """
        return self.entries.get(entry_id)
    
    def get_entries_by_type(self, entry_type: EntryType) -> List[BlackboardEntry]:
        """
        Get all entries of a specific type
        
        Args:
            entry_type: Type of entries to get
            
        Returns:
            List[BlackboardEntry]: List of entries of the specified type
        """
        return [entry for entry in self.entries.values() if entry.entry_type == entry_type]
    
    def get_entries_by_status(self, status: EntryStatus) -> List[BlackboardEntry]:
        """
        Get all entries with a specific status
        
        Args:
            status: Status of entries to get
            
        Returns:
            List[BlackboardEntry]: List of entries with the specified status
        """
        return [entry for entry in self.entries.values() if entry.status == status]
    
    def get_entries_by_source(self, source: ExpertRole) -> List[BlackboardEntry]:
        """
        Get all entries from a specific source
        
        Args:
            source: Source of entries to get
            
        Returns:
            List[BlackboardEntry]: List of entries from the specified source
        """
        return [entry for entry in self.entries.values() if entry.source == source]
    
    def query_entries(self, **kwargs) -> List[BlackboardEntry]:
        """
        Query entries based on multiple criteria
        
        Args:
            **kwargs: Criteria to filter by (e.g., entry_type, status, source)
            
        Returns:
            List[BlackboardEntry]: List of entries matching the criteria
        """
        result = list(self.entries.values())
        
        for key, value in kwargs.items():
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
        
        return result
    
    def register_observer(self, observer) -> None:
        """
        Register an observer to be notified of blackboard changes
        
        Args:
            observer: Observer to register
        """
        if observer not in self.observers:
            self.observers.append(observer)
    
    def notify_observers(self, event_type: str, data: Any) -> None:
        """
        Notify all observers of a change
        
        Args:
            event_type: Type of event (e.g., 'entry_added', 'entry_updated')
            data: Data associated with the event
        """
        for observer in self.observers:
            observer.on_blackboard_event(event_type, data)
    
    def log_action(self, action: str, details: str) -> None:
        """
        Log an action to the blackboard history
        
        Args:
            action: Type of action
            details: Details of the action
        """
        timestamp = datetime.now()
        self.history.append((timestamp, action, details))
        logger.debug(f"{timestamp} - {action}: {details}")
    
    def _create_deduplication_key(self, entry: BlackboardEntry) -> str:
        """
        Create a key for deduplication based on entry properties
        
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
    
    def print_state(self) -> None:
        """Print the current state of the blackboard"""
        print("\n=== BLACKBOARD STATE ===")
        print(f"Total entries: {len(self.entries)}")
        
        # Group entries by type
        entries_by_type = {}
        for entry_type in EntryType:
            entries = self.get_entries_by_type(entry_type)
            if entries:
                entries_by_type[entry_type] = entries
        
        # Print entries by type
        for entry_type, entries in entries_by_type.items():
            print(f"\n{entry_type.name} ({len(entries)}):")
            for _, entry in sorted([(e.entry_id, e) for e in entries]):
                print(f"  - {entry.content} (Status: {entry.status.name})")
