from typing import Optional
from typing import Literal
from pydantic import BaseModel,Field
AssetType=Literal['Website','Server']
Exposure=Literal['Internal facing','External facing','Unknown']
Severity=Literal['Critical','High','Medium','Low','Informational']
class Login(BaseModel): email:str; password:str=Field(min_length=1,max_length=256)
class AssetCreate(BaseModel):
    id:str=Field(min_length=2,max_length=120); name:str=Field(min_length=1,max_length=255); kind:AssetType
    classification:Exposure='Unknown'; owner:str=''; environment:str='Unknown'; criticality:Literal['Critical','High','Medium','Low']='Medium'; compliance:Optional[int]=Field(None,ge=0,le=100); waf:Optional[str]=None; attributes:dict=Field(default_factory=dict)
class AssetUpdate(BaseModel):
    name:Optional[str]=None; classification:Optional[Exposure]=None; owner:Optional[str]=None; environment:Optional[str]=None; criticality:Optional[Literal['Critical','High','Medium','Low']]=None; compliance:Optional[int]=Field(None,ge=0,le=100); status:Optional[Literal['Active','Quarantined','Retired']]=None; waf:Optional[str]=None; attributes:Optional[dict]=None
class FindingCreate(BaseModel):
    id:str=Field(min_length=1,max_length=150); asset_id:str; source:str='manual'; source_finding_id:Optional[str]=None; title:str; cve:Optional[str]=None; severity:Severity; state:Literal['Open','In Progress','Resolved','Accepted Risk']='Open'; first_seen:Optional[str]=None; last_seen:Optional[str]=None; due_at:Optional[str]=None; cvss:Optional[float]=Field(None,ge=0,le=10); epss:Optional[float]=Field(None,ge=0,le=1); kev:bool=False; evidence:dict=Field(default_factory=dict)
class ExceptionCreate(BaseModel): asset_id:str; finding_id:Optional[str]=None; reason:str=Field(min_length=10,max_length=3000); expires_at:str
class ReviewDecision(BaseModel): decision:Literal['Approve','Reject']; note:str=Field(min_length=3,max_length=1000)
class WorkflowCreate(BaseModel): kind:Literal['Rescan','FalsePositive','Remediation','SLAReview']; asset_id:Optional[str]=None; finding_id:Optional[str]=None; payload:dict=Field(default_factory=dict)
class ContainmentRequest(BaseModel): asset_id:str; action:Literal['Quarantine','Release']; acknowledge_impact:bool=False
