"""
Command pattern implementations for the policy implementation system.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry

class BlackboardCommand(ABC):
    """Abstract base class for blackboard commands"""
    
    @abstractmethod
    def execute(self, blackboard: BlackboardInterface) -> Any:
        """
        Execute the command on the blackboard
        
        Args:
            blackboard: Blackboard to execute the command on
            
        Returns:
            Any: Result of the command
        """
        pass
    
    @abstractmethod
    def undo(self, blackboard: BlackboardInterface) -> bool:
        """
        Undo the command on the blackboard
        
        Args:
            blackboard: Blackboard to undo the command on
            
        Returns:
            bool: True if the command was undone successfully
        """
        pass

class AddEntryCommand(BlackboardCommand):
    """Command to add an entry to the blackboard"""
    
    def __init__(self, entry: BlackboardEntry):
        """
        Initialize the command
        
        Args:
            entry: Entry to add
        """
        self.entry = entry
        self.added_entry_id = None
    
    def execute(self, blackboard: BlackboardInterface) -> str:
        """
        Add the entry to the blackboard
        
        Args:
            blackboard: Blackboard to add the entry to
            
        Returns:
            str: ID of the added entry
        """
        self.added_entry_id = blackboard.add_entry(self.entry)
        return self.added_entry_id
    
    def undo(self, blackboard: BlackboardInterface) -> bool:
        """
        Remove the entry from the blackboard
        
        Args:
            blackboard: Blackboard to remove the entry from
            
        Returns:
            bool: True if the entry was removed
        """
        if self.added_entry_id and self.added_entry_id in blackboard.entries:
            del blackboard.entries[self.added_entry_id]
            blackboard.log_action("UNDO_ADD_ENTRY", f"Removed entry {self.added_entry_id}")
            return True
        return False

class UpdateEntryCommand(BlackboardCommand):
    """Command to update an entry in the blackboard"""
    
    def __init__(self, entry_id: str, **kwargs):
        """
        Initialize the command
        
        Args:
            entry_id: ID of the entry to update
            **kwargs: Attributes to update
        """
        self.entry_id = entry_id
        self.updates = kwargs
        self.old_values = {}
    
    def execute(self, blackboard: BlackboardInterface) -> bool:
        """
        Update the entry in the blackboard
        
        Args:
            blackboard: Blackboard to update the entry in
            
        Returns:
            bool: True if the entry was updated
        """
        entry = blackboard.get_entry(self.entry_id)
        if not entry:
            return False
            
        # Save old values for undo
        for key in self.updates:
            if hasattr(entry, key):
                self.old_values[key] = getattr(entry, key)
        
        # Perform update
        return blackboard.update_entry(self.entry_id, **self.updates)
    
    def undo(self, blackboard: BlackboardInterface) -> bool:
        """
        Restore the entry to its previous state
        
        Args:
            blackboard: Blackboard to restore the entry in
            
        Returns:
            bool: True if the entry was restored
        """
        if self.old_values:
            result = blackboard.update_entry(self.entry_id, **self.old_values)
            if result:
                blackboard.log_action("UNDO_UPDATE_ENTRY", f"Restored entry {self.entry_id} to previous state")
            return result
        return False

class CommandProcessor:
    """Processes commands for the blackboard"""
    
    def __init__(self, blackboard: BlackboardInterface):
        """
        Initialize the command processor
        
        Args:
            blackboard: Blackboard to process commands for
        """
        self.blackboard = blackboard
        self.command_history = []
        self.undo_history = []
    
    def execute_command(self, command: BlackboardCommand) -> Any:
        """
        Execute a command and add it to history
        
        Args:
            command: Command to execute
            
        Returns:
            Any: Result of the command
        """
        result = command.execute(self.blackboard)
        self.command_history.append(command)
        return result
    
    def undo_last_command(self) -> bool:
        """
        Undo the last command
        
        Returns:
            bool: True if the command was undone
        """
        if not self.command_history:
            return False
            
        command = self.command_history.pop()
        result = command.undo(self.blackboard)
        if result:
            self.undo_history.append(command)
        return result
    
    def redo_last_command(self) -> bool:
        """
        Redo the last undone command
        
        Returns:
            bool: True if the command was redone
        """
        if not self.undo_history:
            return False
            
        command = self.undo_history.pop()
        result = command.execute(self.blackboard)
        if result:
            self.command_history.append(command)
        return result
