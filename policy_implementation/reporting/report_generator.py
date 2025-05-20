"""
Base report generator for the policy implementation system.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

class ReportGenerator(ABC):
    """Base class for report generators"""
    
    def __init__(self, blackboard: BlackboardInterface, mediator=None):
        """
        Initialize the report generator
        
        Args:
            blackboard: Blackboard to generate reports for
            mediator: Optional mediator for communication
        """
        self.blackboard = blackboard
        self.mediator = mediator
        self.events = []
        
        # Register as observer of the blackboard
        if hasattr(blackboard, 'register_observer'):
            blackboard.register_observer(self)
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Record blackboard events for reporting
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        self.events.append((datetime.now(), event_type, data))
    
    def set_mediator(self, mediator) -> None:
        """
        Set the mediator for this report generator
        
        Args:
            mediator: Mediator to use
        """
        self.mediator = mediator
    
    @abstractmethod
    def generate_report(self) -> str:
        """
        Generate a report based on the blackboard state
        
        Returns:
            str: The generated report
        """
        pass
    
    def get_active_entries(self) -> List:
        """
        Get active entries (not rejected)
        
        Returns:
            List: List of active entries
        """
        return [e for e in self.blackboard.entries.values() 
                if e.status != EntryStatus.REJECTED]
    
    def get_rejected_entries(self) -> List:
        """
        Get rejected entries
        
        Returns:
            List: List of rejected entries
        """
        return [e for e in self.blackboard.entries.values() 
                if e.status == EntryStatus.REJECTED]
    
    def get_entries_by_type_and_status(self, entry_type: EntryType, status: EntryStatus) -> List:
        """
        Get entries by type and status
        
        Args:
            entry_type: Type of entries to get
            status: Status of entries to get
            
        Returns:
            List: List of entries matching the criteria
        """
        return [e for e in self.blackboard.entries.values() 
                if e.entry_type == entry_type and e.status == status]
    
    def get_solutions_by_issue(self) -> Dict:
        """
        Group solutions by the issues they address
        
        Returns:
            Dict: Dictionary of issue_id -> list of solutions
        """
        # Get original issues
        original_issues = [
            entry for entry in self.blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE and entry.rule_id is None
        ]
        
        # Initialize dictionary
        solutions_by_issue = {issue.entry_id: [] for issue in original_issues}
        
        # Get all active solutions
        solutions = [e for e in self.blackboard.entries.values() 
                    if e.entry_type == EntryType.SOLUTION and e.status != EntryStatus.REJECTED]
        
        # Add solutions to their respective issues
        for solution in solutions:
            for rel_id in solution.related_entries:
                if rel_id in solutions_by_issue:
                    solutions_by_issue[rel_id].append(solution)
        
        return solutions_by_issue
    
    def get_decisions_by_source(self) -> Dict:
        """
        Group decisions by source
        
        Returns:
            Dict: Dictionary of source -> list of decisions
        """
        # Get all active decisions
        decisions = [e for e in self.blackboard.entries.values() 
                    if e.entry_type == EntryType.DECISION and e.status != EntryStatus.REJECTED]
        
        # Initialize dictionary
        decisions_by_source = {}
        
        # Add decisions to their respective sources
        for decision in decisions:
            source = decision.source.name if decision.source else "Unknown"
            if source not in decisions_by_source:
                decisions_by_source[source] = []
            decisions_by_source[source].append(decision)
        
        return decisions_by_source
