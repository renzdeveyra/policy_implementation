"""
Rule evaluation strategies for the policy implementation system.
"""
from abc import ABC, abstractmethod
from typing import List
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.rule import Rule

class RuleEvaluationStrategy(ABC):
    """Strategy for evaluating rules"""
    
    @abstractmethod
    def evaluate_rules(self, rules: List[Rule], blackboard: BlackboardInterface) -> List[Rule]:
        """
        Evaluate rules against the blackboard
        
        Args:
            rules: Rules to evaluate
            blackboard: Blackboard to evaluate against
            
        Returns:
            List[Rule]: List of applicable rules
        """
        pass

class PriorityBasedEvaluation(RuleEvaluationStrategy):
    """Evaluate rules based on priority"""
    
    def evaluate_rules(self, rules: List[Rule], blackboard: BlackboardInterface) -> List[Rule]:
        """
        Evaluate rules by priority (highest first)
        
        Args:
            rules: Rules to evaluate
            blackboard: Blackboard to evaluate against
            
        Returns:
            List[Rule]: List of applicable rules sorted by priority
        """
        applicable_rules = [r for r in rules if r.evaluate(blackboard)]
        applicable_rules.sort(key=lambda r: r.priority, reverse=True)
        return applicable_rules

class ConfidenceBasedEvaluation(RuleEvaluationStrategy):
    """Evaluate rules based on confidence"""
    
    def evaluate_rules(self, rules: List[Rule], blackboard: BlackboardInterface) -> List[Rule]:
        """
        Evaluate rules by confidence (highest first)
        
        Args:
            rules: Rules to evaluate
            blackboard: Blackboard to evaluate against
            
        Returns:
            List[Rule]: List of applicable rules sorted by confidence
        """
        applicable_rules = []
        for rule in rules:
            if rule.evaluate(blackboard):
                # Calculate a confidence score for this rule
                confidence = self._calculate_rule_confidence(rule, blackboard)
                applicable_rules.append((rule, confidence))
        
        # Sort by confidence
        applicable_rules.sort(key=lambda x: x[1], reverse=True)
        return [r for r, _ in applicable_rules]
    
    def _calculate_rule_confidence(self, rule: Rule, blackboard: BlackboardInterface) -> float:
        """
        Calculate a confidence score for a rule
        
        Args:
            rule: Rule to calculate confidence for
            blackboard: Blackboard to evaluate against
            
        Returns:
            float: Confidence score
        """
        # This could be based on past success rate, relevance to current issues, etc.
        # For now, use a simple formula based on priority and activation count
        base_confidence = rule.priority / 5.0  # Normalize to 0-1 range
        
        # Rules that have been successful in the past get a boost
        activation_factor = min(rule.activation_count / 10.0, 0.5)  # Cap at 0.5
        
        return base_confidence + activation_factor

class ActivationCountBasedEvaluation(RuleEvaluationStrategy):
    """Evaluate rules based on activation count"""
    
    def __init__(self, prefer_less_used=True):
        """
        Initialize the strategy
        
        Args:
            prefer_less_used: If True, prefer rules that have been used less
        """
        self.prefer_less_used = prefer_less_used
    
    def evaluate_rules(self, rules: List[Rule], blackboard: BlackboardInterface) -> List[Rule]:
        """
        Evaluate rules by activation count
        
        Args:
            rules: Rules to evaluate
            blackboard: Blackboard to evaluate against
            
        Returns:
            List[Rule]: List of applicable rules sorted by activation count
        """
        applicable_rules = [r for r in rules if r.evaluate(blackboard)]
        
        if self.prefer_less_used:
            # Prefer rules that have been used less
            applicable_rules.sort(key=lambda r: r.activation_count)
        else:
            # Prefer rules that have been used more (proven effective)
            applicable_rules.sort(key=lambda r: r.activation_count, reverse=True)
        
        return applicable_rules

class CompositeEvaluation(RuleEvaluationStrategy):
    """Combine multiple evaluation strategies"""
    
    def __init__(self, strategies: List[RuleEvaluationStrategy], weights: List[float] = None):
        """
        Initialize the strategy
        
        Args:
            strategies: List of strategies to combine
            weights: Optional weights for each strategy
        """
        self.strategies = strategies
        self.weights = weights or [1.0] * len(strategies)
        
        # Normalize weights
        total_weight = sum(self.weights)
        self.weights = [w / total_weight for w in self.weights]
    
    def evaluate_rules(self, rules: List[Rule], blackboard: BlackboardInterface) -> List[Rule]:
        """
        Evaluate rules using multiple strategies
        
        Args:
            rules: Rules to evaluate
            blackboard: Blackboard to evaluate against
            
        Returns:
            List[Rule]: List of applicable rules
        """
        applicable_rules = [r for r in rules if r.evaluate(blackboard)]
        
        if not applicable_rules:
            return []
        
        # Calculate scores for each rule using each strategy
        rule_scores = {rule: 0.0 for rule in applicable_rules}
        
        for strategy, weight in zip(self.strategies, self.weights):
            # Get the ordering from this strategy
            strategy_rules = strategy.evaluate_rules(applicable_rules, blackboard)
            
            # Assign scores based on position (higher position = higher score)
            for i, rule in enumerate(strategy_rules):
                # Normalize score to 0-1 range
                score = 1.0 - (i / len(strategy_rules))
                rule_scores[rule] += score * weight
        
        # Sort by final score
        scored_rules = [(rule, score) for rule, score in rule_scores.items()]
        scored_rules.sort(key=lambda x: x[1], reverse=True)
        
        return [rule for rule, _ in scored_rules]
