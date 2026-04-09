from pydantic import BaseModel
from typing import List, Optional

class StepBase(BaseModel):
    step_name: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    ioc_count: int = 0
    cve_count: int = 0
    error_message: Optional[str] = None

class Step(StepBase):
    logs: Optional[List[str]] = []

class RunBase(BaseModel):
    source_name: str
    source_type: str
    status_global: str = "pending"

class RunCreate(RunBase):
    pass

class Run(RunBase):
    id: int
    run_id: str
    created_at: str
    updated_at: Optional[str] = None
    steps: List[Step] = []
