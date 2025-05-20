"""
Rule classes and rule registry for the policy implementation system.
"""
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Callable, Optional
from policy_implementation.core.enums import RuleType, ExpertRole, PRIORITY_LEVELS
from policy_implementation.core.entry import BlackboardEntry

logger = logging.getLogger(__name__)

class Rule:
    """Represents a rule in the expert system"""
    
    def __init__(self, 
                 rule_id: str, 
                 rule_type: RuleType, 
                 condition: Callable, 
                 action: Callable, 
                 description: str, 
                 source: ExpertRole, 
                 priority: Optional[float] = None, 
                 category: Optional[str] = None):
        """
        Initialize a rule
        
        Args:
            rule_id: Unique identifier for the rule
            rule_type: Type of rule
            condition: Function that evaluates if the rule should be applied
            action: Function that applies the rule
            description: Description of the rule
            source: Expert role that owns the rule
            priority: Priority of the rule (higher values = higher priority)
            category: Category of the rule
        """
        self.rule_id = rule_id
        self.rule_type = rule_type
        self.condition = condition
        self.action = action
        self.description = description
        self.source = source
        self.priority = priority or PRIORITY_LEVELS.get(rule_type, 1.0)
        self.category = category or rule_type.name
        self.activation_count = 0
    
    def evaluate(self, blackboard) -> bool:
        """
        Evaluate if the rule should be applied
        
        Args:
            blackboard: The blackboard to evaluate against
            
        Returns:
            bool: True if the rule should be applied
        """
        try:
            return self.condition(blackboard)
        except Exception as e:
            logger.error(f"Error evaluating rule {self.rule_id}: {e}")
            return False
    
    def execute(self, blackboard) -> List[BlackboardEntry]:
        """
        Execute the rule
        
        Args:
            blackboard: The blackboard to execute against
            
        Returns:
            List[BlackboardEntry]: List of new entries created by the rule
        """
        try:
            new_entries = self.action(blackboard)
            self.activation_count += 1
            return new_entries
        except Exception as e:
            logger.error(f"Error executing rule {self.rule_id}: {e}")
            return []
    
    def __str__(self) -> str:
        """String representation of the rule"""
        return f"Rule {self.rule_id}: {self.description} (Type: {self.rule_type.name}, Priority: {self.priority})"

class CompositeRule(Rule):
    """A rule composed of multiple sub-rules"""
    
    def __init__(self, 
                 rule_id: str, 
                 rule_type: RuleType, 
                 description: str, 
                 source: ExpertRole, 
                 priority: Optional[float] = None, 
                 category: Optional[str] = None):
        """
        Initialize a composite rule
        
        Args:
            rule_id: Unique identifier for the rule
            rule_type: Type of rule
            description: Description of the rule
            source: Expert role that owns the rule
            priority: Priority of the rule (higher values = higher priority)
            category: Category of the rule
        """
        super().__init__(
            rule_id=rule_id,
            rule_type=rule_type,
            condition=self._evaluate_conditions,
            action=self._execute_actions,
            description=description,
            source=source,
            priority=priority,
            category=category
        )
        self.sub_rules = []
        self.condition_operator = "AND"  # Can be "AND" or "OR"
    
    def add_sub_rule(self, rule: Rule) -> None:
        """
        Add a sub-rule to this composite rule
        
        Args:
            rule: Rule to add
        """
        self.sub_rules.append(rule)
    
    def set_condition_operator(self, operator: str) -> None:
        """
        Set the operator for combining conditions (AND/OR)
        
        Args:
            operator: Operator to use ("AND" or "OR")
        """
        if operator in ["AND", "OR"]:
            self.condition_operator = operator
    
    def _evaluate_conditions(self, blackboard) -> bool:
        """
        Evaluate conditions of all sub-rules
        
        Args:
            blackboard: The blackboard to evaluate against
            
        Returns:
            bool: True if the conditions are met
        """
        if not self.sub_rules:
            return False
            
        if self.condition_operator == "AND":
            return all(rule.evaluate(blackboard) for rule in self.sub_rules)
        else:  # OR
            return any(rule.evaluate(blackboard) for rule in self.sub_rules)
    
    def _execute_actions(self, blackboard) -> List[BlackboardEntry]:
        """
        Execute actions of all applicable sub-rules
        
        Args:
            blackboard: The blackboard to execute against
            
        Returns:
            List[BlackboardEntry]: List of new entries created by the sub-rules
        """
        new_entries = []
        
        for rule in self.sub_rules:
            if rule.evaluate(blackboard):
                entries = rule.execute(blackboard)
                if entries:
                    new_entries.extend(entries)
        
        return new_entries

class RuleRegistry:
    """Central registry for all rules in the system"""
    
    def __init__(self):
        """Initialize the rule registry"""
        self.rules = {}  # Dictionary of rule_id -> Rule
        self.rule_categories = {}  # Dictionary of category -> list of rule_ids
    
    def register_rule(self, rule: Rule) -> None:
        """
        Register a rule in the registry
        
        Args:
            rule: Rule to register
        """
        self.rules[rule.rule_id] = rule
        
        # Add to category
        if rule.category not in self.rule_categories:
            self.rule_categories[rule.category] = []
        self.rule_categories[rule.category].append(rule.rule_id)
    
    def get_rules_by_category(self, category: str) -> List[Rule]:
        """
        Get all rules in a specific category
        
        Args:
            category: Category to get rules for
            
        Returns:
            List[Rule]: List of rules in the category
        """
        rule_ids = self.rule_categories.get(category, [])
        return [self.rules[rule_id] for rule_id in rule_ids]
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """
        Get a specific rule by ID
        
        Args:
            rule_id: ID of the rule to get
            
        Returns:
            Rule or None: The rule if found, None otherwise
        """
        return self.rules.get(rule_id)
    
    def get_rules_by_source(self, source: ExpertRole) -> List[Rule]:
        """
        Get all rules from a specific source
        
        Args:
            source: Source to get rules for
            
        Returns:
            List[Rule]: List of rules from the source
        """
        return [rule for rule in self.rules.values() if rule.source == source]
    
    def get_rules_by_type(self, rule_type: RuleType) -> List[Rule]:
        """
        Get all rules of a specific type
        
        Args:
            rule_type: Type of rules to get
            
        Returns:
            List[Rule]: List of rules of the specified type
        """
        return [rule for rule in self.rules.values() if rule.rule_type == rule_type]

class RuleFactory:
    """Factory for creating rules"""
    
    @staticmethod
    def create_rule(rule_type: RuleType, 
                   rule_id: str, 
                   description: str, 
                   source: ExpertRole, 
                   condition: Callable, 
                   action: Callable, 
                   priority: Optional[float] = None, 
                   category: Optional[str] = None) -> Rule:
        """
        Create a rule of the specified type
        
        Args:
            rule_type: Type of rule to create
            rule_id: Unique identifier for the rule
            description: Description of the rule
            source: Expert role that owns the rule
            condition: Function that evaluates if the rule should be applied
            action: Function that applies the rule
            priority: Priority of the rule (higher values = higher priority)
            category: Category of the rule
            
        Returns:
            Rule: The created rule
        """
        if category is None:
            category = rule_type.name
            
        return Rule(
            rule_id=rule_id,
            rule_type=rule_type,
            description=description,
            source=source,
            condition=condition,
            action=action,
            priority=priority,
            category=category
        )
    
    @staticmethod
    def create_from_config(config: Dict[str, Any], source: ExpertRole) -> Rule:
        """
        Create a rule from a configuration dictionary
        
        Args:
            config: Configuration dictionary
            source: Expert role that owns the rule
            
        Returns:
            Rule: The created rule
        """
        rule_type = RuleType[config['rule_type']]
        
        # Create condition function from string or use provided function
        if isinstance(config['condition'], str):
            condition_code = compile(config['condition'], '<string>', 'eval')
            condition = lambda bb, code=condition_code: eval(code, {'bb': bb})
        else:
            condition = config['condition']
            
        # Create action function from string or use provided function
        if isinstance(config['action'], str):
            action_code = compile(config['action'], '<string>', 'exec')
            def action_func(bb, code=action_code):
                local_vars = {'bb': bb, 'result': []}
                exec(code, {}, local_vars)
                return local_vars.get('result', [])
            action = action_func
        else:
            action = config['action']
        
        return RuleFactory.create_rule(
            rule_type=rule_type,
            rule_id=config['rule_id'],
            description=config['description'],
            source=source,
            condition=condition,
            action=action,
            priority=config.get('priority'),
            category=config.get('category')
        )
