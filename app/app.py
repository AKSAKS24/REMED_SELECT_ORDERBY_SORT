# main.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# Import your processing modules
from app.select import process_select
from app.sort import process_sort
from app.orderby import process_orderby
from app.read_statement import process_read

app = FastAPI()


# Payload structure
class Payload(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    code: str


# Response structure
class ResponseModel(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    original_code: str
    remediated_code: str


async def process_abap_code(payload: Payload) -> ResponseModel:
    """
    Process ABAP code through select, sort, orderby, read_statement modules
    sequentially and add Pwc tag where required.
    """
    original_code = payload.code
    corrected_code = original_code

    # Step 1: Process SELECT statements
    corrected_code = process_select(corrected_code)

    # Step 2: Process SORT statements (FOR ALL ENTRIES)
    corrected_code = process_sort(corrected_code)

    # Step 3: Process ORDER BY statements (non-FAE SELECT)
    corrected_code = process_orderby(corrected_code)

    # Step 4: Process READ TABLE statements
    corrected_code = process_read(corrected_code)

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=corrected_code,
    )


@app.post("/remediate_abap", response_model=ResponseModel)
async def remediate_abap(payload: Payload):
    return await process_abap_code(payload)

