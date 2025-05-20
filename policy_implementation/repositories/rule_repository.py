"""
RuleRepository interface and implementations for the policy implementation system.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from policy_implementation.core.rule import Rule
from policy_implementation.core.enums import RuleType, ExpertRole

class RuleRepository(ABC):
    """Abstract repository for rules"""

    @abstractmethod
    def add(self, rule: Rule) -> None:
        """
        Add a rule to the repository

        Args:
            rule: Rule to add
        """
        pass

    @abstractmethod
    def register_rule(self, rule: Rule) -> None:
        """
        Register a rule in the repository (alias for add)

        Args:
            rule: Rule to register
        """
        pass

    @abstractmethod
    def get(self, rule_id: str) -> Optional[Rule]:
        """
        Get a rule by ID

        Args:
            rule_id: ID of the rule to get

        Returns:
            Rule or None: The rule if found, None otherwise
        """
        pass

    @abstractmethod
    def get_by_source(self, source: ExpertRole) -> List[Rule]:
        """
        Get rules by source

        Args:
            source: Source to get rules for

        Returns:
            List[Rule]: List of rules from the source
        """
        pass

    @abstractmethod
    def get_by_type(self, rule_type: RuleType) -> List[Rule]:
        """
        Get rules by type

        Args:
            rule_type: Type to get rules for

        Returns:
            List[Rule]: List of rules of the type
        """
        pass

    @abstractmethod
    def get_by_category(self, category: str) -> List[Rule]:
        """
        Get rules by category

        Args:
            category: Category to get rules for

        Returns:
            List[Rule]: List of rules in the category
        """
        pass

    @abstractmethod
    def get_all(self) -> List[Rule]:
        """
        Get all rules in the repository

        Returns:
            List[Rule]: List of all rules
        """
        pass

    @abstractmethod
    def delete(self, rule_id: str) -> bool:
        """
        Delete a rule from the repository

        Args:
            rule_id: ID of the rule to delete

        Returns:
            bool: True if the rule was deleted
        """
        pass

class InMemoryRuleRepository(RuleRepository):
    """In-memory implementation of the rule repository"""

    def __init__(self):
        """Initialize the repository"""
        self.rules = {}  # Dictionary of rule_id -> Rule
        self.rule_categories = {}  # Dictionary of category -> list of rule_ids
        self.rule_sources = {}  # Dictionary of source -> list of rule_ids
        self.rule_types = {}  # Dictionary of type -> list of rule_ids

    def add(self, rule: Rule) -> None:
        """
        Add a rule to the repository

        Args:
            rule: Rule to add
        """
        self.rules[rule.rule_id] = rule

        # Add to category index
        if rule.category not in self.rule_categories:
            self.rule_categories[rule.category] = []
        self.rule_categories[rule.category].append(rule.rule_id)

        # Add to source index
        source_name = rule.source.name
        if source_name not in self.rule_sources:
            self.rule_sources[source_name] = []
        self.rule_sources[source_name].append(rule.rule_id)

        # Add to type index
        type_name = rule.rule_type.name
        if type_name not in self.rule_types:
            self.rule_types[type_name] = []
        self.rule_types[type_name].append(rule.rule_id)

    def register_rule(self, rule: Rule) -> None:
        """
        Register a rule in the repository (alias for add)

        Args:
            rule: Rule to register
        """
        self.add(rule)

    def get(self, rule_id: str) -> Optional[Rule]:
        """
        Get a rule by ID

        Args:
            rule_id: ID of the rule to get

        Returns:
            Rule or None: The rule if found, None otherwise
        """
        return self.rules.get(rule_id)

    def get_by_source(self, source: ExpertRole) -> List[Rule]:
        """
        Get rules by source

        Args:
            source: Source to get rules for

        Returns:
            List[Rule]: List of rules from the source
        """
        source_name = source.name
        rule_ids = self.rule_sources.get(source_name, [])
        return [self.rules[rule_id] for rule_id in rule_ids if rule_id in self.rules]

    def get_by_type(self, rule_type: RuleType) -> List[Rule]:
        """
        Get rules by type

        Args:
            rule_type: Type to get rules for

        Returns:
            List[Rule]: List of rules of the type
        """
        type_name = rule_type.name
        rule_ids = self.rule_types.get(type_name, [])
        return [self.rules[rule_id] for rule_id in rule_ids if rule_id in self.rules]

    def get_by_category(self, category: str) -> List[Rule]:
        """
        Get rules by category

        Args:
            category: Category to get rules for

        Returns:
            List[Rule]: List of rules in the category
        """
        rule_ids = self.rule_categories.get(category, [])
        return [self.rules[rule_id] for rule_id in rule_ids if rule_id in self.rules]

    def get_all(self) -> List[Rule]:
        """
        Get all rules in the repository

        Returns:
            List[Rule]: List of all rules
        """
        return list(self.rules.values())

    def delete(self, rule_id: str) -> bool:
        """
        Delete a rule from the repository

        Args:
            rule_id: ID of the rule to delete

        Returns:
            bool: True if the rule was deleted
        """
        if rule_id not in self.rules:
            return False

        rule = self.rules[rule_id]

        # Remove from category index
        if rule.category in self.rule_categories and rule_id in self.rule_categories[rule.category]:
            self.rule_categories[rule.category].remove(rule_id)

        # Remove from source index
        source_name = rule.source.name
        if source_name in self.rule_sources and rule_id in self.rule_sources[source_name]:
            self.rule_sources[source_name].remove(rule_id)

        # Remove from type index
        type_name = rule.rule_type.name
        if type_name in self.rule_types and rule_id in self.rule_types[type_name]:
            self.rule_types[type_name].remove(rule_id)

        # Remove from rules dictionary
        del self.rules[rule_id]

        return True
