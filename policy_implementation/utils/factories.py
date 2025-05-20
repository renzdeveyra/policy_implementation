"""
Factory classes for the policy implementation system.
"""
import uuid
from typing import List, Dict, Any, Optional
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole

class EntryFactory:
    """Factory for creating blackboard entries"""
    
    @staticmethod
    def create_entry(entry_type: EntryType, 
                    content: str, 
                    source: Optional[ExpertRole] = None, 
                    rule_id: Optional[str] = None, 
                    status: EntryStatus = EntryStatus.NEW, 
                    confidence: float = 1.0, 
                    related_entries: Optional[List[str]] = None, 
                    metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create a new blackboard entry
        
        Args:
            entry_type: Type of entry to create
            content: Content of the entry
            source: Source of the entry
            rule_id: ID of the rule that created the entry
            status: Status of the entry
            confidence: Confidence score for the entry
            related_entries: List of related entry IDs
            metadata: Additional metadata for the entry
            
        Returns:
            BlackboardEntry: The created entry
        """
        entry_id = f"{entry_type.name.lower()}_{uuid.uuid4()}"
        
        return BlackboardEntry(
            entry_id=entry_id,
            entry_type=entry_type,
            content=content,
            source=source,
            rule_id=rule_id,
            status=status,
            confidence=confidence,
            related_entries=related_entries or [],
            metadata=metadata or {}
        )
    
    @staticmethod
    def create_issue(content: str, 
                    source: ExpertRole, 
                    confidence: float = 0.9, 
                    metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create an issue entry
        
        Args:
            content: Content of the issue
            source: Source of the issue
            confidence: Confidence score for the issue
            metadata: Additional metadata for the issue
            
        Returns:
            BlackboardEntry: The created issue
        """
        return EntryFactory.create_entry(
            entry_type=EntryType.ISSUE,
            content=content,
            source=source,
            confidence=confidence,
            metadata=metadata or {"issue_type": "general"}
        )
    
    @staticmethod
    def create_directive(content: str, 
                        source: ExpertRole, 
                        confidence: float = 0.95, 
                        metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create a directive entry
        
        Args:
            content: Content of the directive
            source: Source of the directive
            confidence: Confidence score for the directive
            metadata: Additional metadata for the directive
            
        Returns:
            BlackboardEntry: The created directive
        """
        return EntryFactory.create_entry(
            entry_type=EntryType.DIRECTIVE,
            content=content,
            source=source,
            confidence=confidence,
            metadata=metadata or {"directive_type": "general"}
        )
    
    @staticmethod
    def create_solution(content: str, 
                       source: ExpertRole, 
                       related_issues: List[str], 
                       rule_id: Optional[str] = None, 
                       confidence: float = 0.85, 
                       metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create a solution entry
        
        Args:
            content: Content of the solution
            source: Source of the solution
            related_issues: List of related issue IDs
            rule_id: ID of the rule that created the solution
            confidence: Confidence score for the solution
            metadata: Additional metadata for the solution
            
        Returns:
            BlackboardEntry: The created solution
        """
        return EntryFactory.create_entry(
            entry_type=EntryType.SOLUTION,
            content=content,
            source=source,
            rule_id=rule_id,
            status=EntryStatus.RESOLVED,
            confidence=confidence,
            related_entries=related_issues,
            metadata=metadata or {"action": "general_solution"}
        )
    
    @staticmethod
    def create_decision(content: str, 
                       source: ExpertRole, 
                       related_entries: List[str], 
                       rule_id: Optional[str] = None, 
                       confidence: float = 0.9, 
                       metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create a decision entry
        
        Args:
            content: Content of the decision
            source: Source of the decision
            related_entries: List of related entry IDs
            rule_id: ID of the rule that created the decision
            confidence: Confidence score for the decision
            metadata: Additional metadata for the decision
            
        Returns:
            BlackboardEntry: The created decision
        """
        return EntryFactory.create_entry(
            entry_type=EntryType.DECISION,
            content=content,
            source=source,
            rule_id=rule_id,
            status=EntryStatus.RESOLVED,
            confidence=confidence,
            related_entries=related_entries,
            metadata=metadata or {"decision_type": "general"}
        )
    
    @staticmethod
    def create_compliance_concern(content: str, 
                                source: ExpertRole, 
                                related_entries: List[str], 
                                rule_id: Optional[str] = None, 
                                confidence: float = 0.9, 
                                metadata: Optional[Dict[str, Any]] = None) -> BlackboardEntry:
        """
        Create a compliance concern entry
        
        Args:
            content: Content of the compliance concern
            source: Source of the compliance concern
            related_entries: List of related entry IDs
            rule_id: ID of the rule that created the compliance concern
            confidence: Confidence score for the compliance concern
            metadata: Additional metadata for the compliance concern
            
        Returns:
            BlackboardEntry: The created compliance concern
        """
        return EntryFactory.create_entry(
            entry_type=EntryType.COMPLIANCE_CONCERN,
            content=content,
            source=source,
            rule_id=rule_id,
            status=EntryStatus.NEW,
            confidence=confidence,
            related_entries=related_entries,
            metadata=metadata or {"concern_type": "general"}
        )
