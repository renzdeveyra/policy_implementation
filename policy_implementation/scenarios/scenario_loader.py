"""
Scenario loading functionality for the policy implementation system.
"""
import json
import os
import uuid
import logging
from typing import Dict, Any, Optional
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

logger = logging.getLogger(__name__)

class ScenarioLoader:
    """Loads scenarios into the blackboard"""
    
    def __init__(self, blackboard: BlackboardInterface):
        """
        Initialize the scenario loader
        
        Args:
            blackboard: Blackboard to load scenarios into
        """
        self.blackboard = blackboard
        self.scenarios = {
            "approval_bottleneck": self._load_approval_bottleneck,
            "compliance_challenge": self._load_compliance_challenge,
            "resource_conflict": self._load_resource_conflict,
            "communication_issues": self._load_communication_issues
        }
    
    def load_scenario(self, scenario_name: str) -> bool:
        """
        Load a scenario into the blackboard
        
        Args:
            scenario_name: Name of the scenario to load
            
        Returns:
            bool: True if the scenario was loaded successfully
        """
        if scenario_name in self.scenarios:
            logger.info(f"Loading scenario: {scenario_name}")
            self.scenarios[scenario_name]()
            return True
        elif os.path.isfile(scenario_name):
            logger.info(f"Loading scenario from file: {scenario_name}")
            return self.load_scenario_from_file(scenario_name)
        else:
            logger.error(f"Unknown scenario: {scenario_name}")
            return False
    
    def load_scenario_from_file(self, filename: str) -> bool:
        """
        Load a scenario from a JSON file
        
        Args:
            filename: Path to the JSON file
            
        Returns:
            bool: True if the scenario was loaded successfully
        """
        try:
            with open(filename, 'r') as f:
                scenario_data = json.load(f)
            
            for entry_data in scenario_data.get('entries', []):
                # Convert string enum names to actual enum values
                entry_type = EntryType[entry_data['entry_type']]
                source = ExpertRole[entry_data['source']] if entry_data.get('source') else None
                status = EntryStatus[entry_data['status']]
                
                self.blackboard.add_entry(BlackboardEntry(
                    entry_id=f"{entry_data.get('type_prefix', 'entry')}_{uuid.uuid4()}",
                    entry_type=entry_type,
                    content=entry_data['content'],
                    source=source,
                    rule_id=entry_data.get('rule_id'),
                    status=status,
                    confidence=entry_data.get('confidence', 1.0),
                    related_entries=entry_data.get('related_entries', []),
                    metadata=entry_data.get('metadata', {})
                ))
            
            logger.info(f"Loaded {len(scenario_data.get('entries', []))} entries from {filename}")
            return True
        except Exception as e:
            logger.error(f"Error loading scenario from file {filename}: {e}")
            return False
    
    def _load_approval_bottleneck(self) -> None:
        """Load the approval bottleneck scenario"""
        # Issue 1: Approval bottleneck
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Approval process for procurement requests takes too long, causing delays in project implementation",
            source=ExpertRole.AA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"issue_type": "process_delay"}
        ))
        
        # Issue 2: Resource allocation
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Shortage of IT resources for implementing the new digital signature system",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.85,
            related_entries=[],
            metadata={"issue_type": "resource_shortage"}
        ))
        
        # Directive 1: New compliance requirement
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Implement new data protection policy in accordance with updated regulations",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.95,
            related_entries=[],
            metadata={"directive_type": "compliance"}
        ))
        
        # Directive 2: Process improvement
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Create new streamlined process for budget approval to reduce bureaucratic delays",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"directive_type": "process_improvement"}
        ))
    
    def _load_compliance_challenge(self) -> None:
        """Load the compliance challenge scenario"""
        # Issue 1: Compliance challenge
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="New regulatory requirements create compliance challenges for existing processes",
            source=ExpertRole.CIA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.95,
            related_entries=[],
            metadata={"issue_type": "compliance_challenge"}
        ))
        
        # Issue 2: Documentation gap
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Insufficient documentation of existing processes makes compliance verification difficult",
            source=ExpertRole.CIA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"issue_type": "documentation_gap"}
        ))
        
        # Directive 1: Compliance deadline
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Achieve full compliance with new regulations within 90 days",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=1.0,
            related_entries=[],
            metadata={"directive_type": "compliance_deadline"}
        ))
        
        # Directive 2: Audit requirement
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Conduct internal audit of all affected processes before external compliance review",
            source=ExpertRole.CIA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.95,
            related_entries=[],
            metadata={"directive_type": "audit_requirement"}
        ))
    
    def _load_resource_conflict(self) -> None:
        """Load the resource conflict scenario"""
        # Issue 1: Competing priorities
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Multiple high-priority projects competing for the same limited resources",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"issue_type": "resource_conflict"}
        ))
        
        # Issue 2: Budget constraints
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Budget constraints prevent hiring additional staff to meet project demands",
            source=ExpertRole.AA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.85,
            related_entries=[],
            metadata={"issue_type": "budget_constraint"}
        ))
        
        # Directive 1: Project deadline
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="All critical projects must be completed by the end of the fiscal year",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.95,
            related_entries=[],
            metadata={"directive_type": "deadline"}
        ))
        
        # Directive 2: Resource optimization
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Optimize resource allocation to maximize project completion rate",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"directive_type": "resource_optimization"}
        ))
    
    def _load_communication_issues(self) -> None:
        """Load the communication issues scenario"""
        # Issue 1: Communication breakdown
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Interdepartmental communication breakdowns causing project delays and misaligned priorities",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.92,
            related_entries=[],
            metadata={"issue_type": "communication_problem"}
        ))
        
        # Issue 2: Information silos
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"issue_{uuid.uuid4()}",
            entry_type=EntryType.ISSUE,
            content="Information silos between departments leading to duplicated efforts and inconsistent policy implementation",
            source=ExpertRole.CIA,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.88,
            related_entries=[],
            metadata={"issue_type": "information_sharing"}
        ))
        
        # Directive 1: Collaboration platform
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Implement new cross-departmental collaboration platform and communication protocols",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.95,
            related_entries=[],
            metadata={"directive_type": "collaboration"}
        ))
        
        # Directive 2: Regular coordination meetings
        self.blackboard.add_entry(BlackboardEntry(
            entry_id=f"directive_{uuid.uuid4()}",
            entry_type=EntryType.DIRECTIVE,
            content="Establish mandatory bi-weekly coordination meetings between department heads",
            source=ExpertRole.DDG,
            rule_id=None,
            status=EntryStatus.NEW,
            confidence=0.9,
            related_entries=[],
            metadata={"directive_type": "coordination"}
        ))
