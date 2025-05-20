"""
Mediator for communication between blackboard components.
"""
import logging
from typing import List, Dict, Any
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry

logger = logging.getLogger(__name__)

class BlackboardMediator:
    """Mediator for communication between blackboard components"""
    
    def __init__(self, blackboard: BlackboardInterface):
        """
        Initialize the mediator
        
        Args:
            blackboard: Blackboard to mediate
        """
        self.blackboard = blackboard
        self.knowledge_sources = []
        self.control_shell = None
        self.report_generators = []
        
        # Register as observer of the blackboard
        self.blackboard.register_observer(self)
    
    def register_knowledge_source(self, knowledge_source) -> None:
        """
        Register a knowledge source with the mediator
        
        Args:
            knowledge_source: Knowledge source to register
        """
        self.knowledge_sources.append(knowledge_source)
        knowledge_source.set_mediator(self)
    
    def register_control_shell(self, control_shell) -> None:
        """
        Register the control shell with the mediator
        
        Args:
            control_shell: Control shell to register
        """
        self.control_shell = control_shell
        control_shell.set_mediator(self)
    
    def register_report_generator(self, report_generator) -> None:
        """
        Register a report generator with the mediator
        
        Args:
            report_generator: Report generator to register
        """
        self.report_generators.append(report_generator)
        report_generator.set_mediator(self)
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Handle blackboard events
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        # Notify knowledge sources
        for ks in self.knowledge_sources:
            ks.on_blackboard_event(event_type, data)
        
        # Notify control shell
        if self.control_shell:
            self.control_shell.on_blackboard_event(event_type, data)
        
        # Notify report generators
        for rg in self.report_generators:
            rg.on_blackboard_event(event_type, data)
    
    def notify_entry_added(self, entry: BlackboardEntry) -> None:
        """
        Notify components that an entry was added
        
        Args:
            entry: Entry that was added
        """
        # Notify knowledge sources
        for ks in self.knowledge_sources:
            ks.on_entry_added(entry)
        
        # Notify control shell
        if self.control_shell:
            self.control_shell.on_entry_added(entry)
        
        # Notify report generators
        for rg in self.report_generators:
            rg.on_entry_added(entry)
    
    def notify_entry_updated(self, entry: BlackboardEntry, old_state: Dict[str, Any]) -> None:
        """
        Notify components that an entry was updated
        
        Args:
            entry: Entry that was updated
            old_state: Previous state of the entry
        """
        # Similar implementation to notify_entry_added
        pass
    
    def activate_knowledge_source(self, knowledge_source) -> List[BlackboardEntry]:
        """
        Request activation of a knowledge source
        
        Args:
            knowledge_source: Knowledge source to activate
            
        Returns:
            List[BlackboardEntry]: New entries created by the knowledge source
        """
        if knowledge_source in self.knowledge_sources and knowledge_source.is_available():
            logger.info(f"Mediator activating knowledge source: {knowledge_source.name}")
            new_entries = knowledge_source.activate(self.blackboard)
            return new_entries
        return []
    
    def get_available_knowledge_sources(self) -> List:
        """
        Get knowledge sources that are available for activation
        
        Returns:
            List: List of available knowledge sources
        """
        return [ks for ks in self.knowledge_sources if ks.is_available()]
