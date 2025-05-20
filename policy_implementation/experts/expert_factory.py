"""
Factory for creating experts for the policy implementation system.
"""
from typing import Dict, Any, Optional
from policy_implementation.core.enums import ExpertRole
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.knowledge_source import KnowledgeSource
from policy_implementation.experts.deputy_director import DeputyDirectorGeneral
from policy_implementation.experts.internal_auditor import ChiefInternalAuditor
from policy_implementation.experts.admin_assistant import AdministrativeAssistant

class ExpertFactory:
    """Factory for creating experts"""
    
    def __init__(self, rule_repository=None):
        """
        Initialize the factory
        
        Args:
            rule_repository: Repository for rules
        """
        self.rule_repository = rule_repository
    
    def create_expert(self, 
                     expert_type: str, 
                     blackboard: BlackboardInterface, 
                     mediator=None, 
                     config: Optional[Dict[str, Any]] = None) -> KnowledgeSource:
        """
        Create an expert of the specified type
        
        Args:
            expert_type: Type of expert to create
            blackboard: Blackboard for the expert to interact with
            mediator: Optional mediator for communication
            config: Optional configuration for the expert
            
        Returns:
            KnowledgeSource: The created expert
            
        Raises:
            ValueError: If the expert type is not recognized
        """
        config = config or {}
        
        if expert_type == "DeputyDirectorGeneral" or expert_type == ExpertRole.DDG.name:
            expert = DeputyDirectorGeneral(blackboard, self.rule_repository)
        elif expert_type == "ChiefInternalAuditor" or expert_type == ExpertRole.CIA.name:
            expert = ChiefInternalAuditor(blackboard, self.rule_repository)
        elif expert_type == "AdministrativeAssistant" or expert_type == ExpertRole.AA.name:
            expert = AdministrativeAssistant(blackboard, self.rule_repository)
        else:
            raise ValueError(f"Unknown expert type: {expert_type}")
        
        # Set mediator if provided
        if mediator:
            expert.set_mediator(mediator)
        
        # Apply configuration
        for key, value in config.items():
            if hasattr(expert, key):
                setattr(expert, key, value)
        
        # Initialize the expert
        expert.initialize()
        
        return expert
