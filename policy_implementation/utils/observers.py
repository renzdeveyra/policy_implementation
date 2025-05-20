"""
Observer pattern implementations for the policy implementation system.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime

class BlackboardObserver(ABC):
    """Interface for observers of blackboard events"""
    
    @abstractmethod
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Called when a blackboard event occurs
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        pass

class EventLogger(BlackboardObserver):
    """Logs blackboard events"""
    
    def __init__(self):
        """Initialize the event logger"""
        self.events = []
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Log a blackboard event
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        self.events.append((datetime.now(), event_type, data))
    
    def get_events(self) -> List:
        """
        Get all logged events
        
        Returns:
            List: List of events
        """
        return self.events
    
    def get_events_by_type(self, event_type: str) -> List:
        """
        Get events of a specific type
        
        Args:
            event_type: Type of events to get
            
        Returns:
            List: List of events of the specified type
        """
        return [(timestamp, event_type, data) for timestamp, et, data in self.events if et == event_type]
    
    def clear(self) -> None:
        """Clear all logged events"""
        self.events = []

class EntryChangeNotifier(BlackboardObserver):
    """Notifies subscribers of changes to entries"""
    
    def __init__(self):
        """Initialize the notifier"""
        self.subscribers = {}
    
    def subscribe(self, entry_id: str, callback) -> None:
        """
        Subscribe to changes to a specific entry
        
        Args:
            entry_id: ID of the entry to subscribe to
            callback: Function to call when the entry changes
        """
        if entry_id not in self.subscribers:
            self.subscribers[entry_id] = []
        self.subscribers[entry_id].append(callback)
    
    def unsubscribe(self, entry_id: str, callback) -> None:
        """
        Unsubscribe from changes to a specific entry
        
        Args:
            entry_id: ID of the entry to unsubscribe from
            callback: Function to unsubscribe
        """
        if entry_id in self.subscribers and callback in self.subscribers[entry_id]:
            self.subscribers[entry_id].remove(callback)
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Handle blackboard events
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        if event_type == "entry_added":
            entry = data
            if entry.entry_id in self.subscribers:
                for callback in self.subscribers[entry.entry_id]:
                    callback("added", entry)
        elif event_type == "entry_updated":
            entry = data.get("entry")
            old_state = data.get("old_state")
            if entry and entry.entry_id in self.subscribers:
                for callback in self.subscribers[entry.entry_id]:
                    callback("updated", entry, old_state)
        elif event_type == "entry_replaced":
            new_entry = data.get("new_entry")
            old_entry = data.get("old_entry")
            if old_entry and old_entry.entry_id in self.subscribers:
                for callback in self.subscribers[old_entry.entry_id]:
                    callback("replaced", old_entry, new_entry)

class BlackboardStatisticsObserver(BlackboardObserver):
    """Collects statistics about blackboard events"""
    
    def __init__(self):
        """Initialize the statistics observer"""
        self.event_counts = {}
        self.entry_type_counts = {}
        self.source_counts = {}
        self.start_time = datetime.now()
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Handle blackboard events
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        # Count events by type
        if event_type not in self.event_counts:
            self.event_counts[event_type] = 0
        self.event_counts[event_type] += 1
        
        # Count entries by type
        if event_type == "entry_added":
            entry = data
            entry_type = entry.entry_type.name
            if entry_type not in self.entry_type_counts:
                self.entry_type_counts[entry_type] = 0
            self.entry_type_counts[entry_type] += 1
            
            # Count entries by source
            if entry.source:
                source = entry.source.name
                if source not in self.source_counts:
                    self.source_counts[source] = 0
                self.source_counts[source] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get collected statistics
        
        Returns:
            Dict[str, Any]: Dictionary of statistics
        """
        return {
            "event_counts": self.event_counts,
            "entry_type_counts": self.entry_type_counts,
            "source_counts": self.source_counts,
            "running_time": (datetime.now() - self.start_time).total_seconds()
        }
