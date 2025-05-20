"""
KnowledgeSource base class for the policy implementation system.
"""
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Optional
from policy_implementation.core.enums import ExpertRole
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.blackboard import BlackboardInterface

logger = logging.getLogger(__name__)

class KnowledgeSource(ABC):
    """Abstract base class for knowledge sources"""

    def __init__(self,
                 role: ExpertRole,
                 name: str,
                 blackboard: BlackboardInterface,
                 rule_registry=None,
                 evaluation_strategy=None):
        """
        Initialize a knowledge source

        Args:
            role: Expert role of this knowledge source
            name: Name of this knowledge source
            blackboard: Blackboard to interact with
            rule_registry: Registry of rules
            evaluation_strategy: Strategy for evaluating rules
        """
        self.role = role
        self.name = name
        self.blackboard = blackboard
        self.rule_registry = rule_registry
        self.rule_ids = []  # IDs of rules owned by this knowledge source
        self.priority = 1.0  # Default priority
        self.last_activated = None
        self.cooldown_period = timedelta(seconds=5)
        self.evaluation_strategy = evaluation_strategy
        self.mediator = None  # Optional mediator for communication

    def is_available(self) -> bool:
        """
        Check if this knowledge source is available for activation

        Returns:
            bool: True if available
        """
        if self.last_activated is None:
            return True

        time_since_last_activation = datetime.now() - self.last_activated
        return time_since_last_activation >= self.cooldown_period

    def activate(self, blackboard: BlackboardInterface) -> List[BlackboardEntry]:
        """
        Activate this knowledge source to contribute to the blackboard

        Args:
            blackboard: Blackboard to contribute to

        Returns:
            List[BlackboardEntry]: List of new entries created
        """
        if not self.is_available():
            logger.debug(f"Knowledge source {self.name} is on cooldown")
            return []

        logger.info(f"Activating knowledge source: {self.name}")
        self.last_activated = datetime.now()

        # Get applicable rules
        applicable_rules = self.get_applicable_rules(blackboard)

        if not applicable_rules:
            logger.debug(f"No applicable rules for {self.name}")
            return []

        # Execute rules
        new_entries = []
        for rule in applicable_rules:
            logger.debug(f"Executing rule: {rule.rule_id}")
            entries = rule.execute(blackboard)
            if entries:
                new_entries.extend(entries)

        logger.info(f"Knowledge source {self.name} created {len(new_entries)} new entries")
        return new_entries

    def get_applicable_rules(self, blackboard: BlackboardInterface) -> List:
        """
        Get rules that are applicable to the current blackboard state

        Args:
            blackboard: Blackboard to evaluate rules against

        Returns:
            List: List of applicable rules
        """
        if self.rule_registry:
            # Get rules from registry
            rules = self.rule_registry.get_by_source(self.role)

            # Filter for applicable rules
            applicable_rules = []
            for rule in rules:
                if rule.evaluate(blackboard):
                    applicable_rules.append(rule)

            # Sort by priority
            applicable_rules.sort(key=lambda r: r.priority, reverse=True)
            return applicable_rules
        else:
            # Subclasses should override this if not using rule registry
            return []

    def add_rule(self, rule) -> None:
        """
        Add a rule to this knowledge source

        Args:
            rule: Rule to add
        """
        if self.rule_registry:
            self.rule_registry.register_rule(rule)
            self.rule_ids.append(rule.rule_id)

    def on_blackboard_event(self, event_type: str, data) -> None:
        """
        Handle blackboard events

        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        # Default implementation does nothing
        pass

    def set_mediator(self, mediator) -> None:
        """
        Set the mediator for this knowledge source

        Args:
            mediator: Mediator to use
        """
        self.mediator = mediator

    @abstractmethod
    def initialize(self) -> None:
        """Initialize this knowledge source with rules"""
        pass
