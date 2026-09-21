"""외부 대상 모듈 연결을 위한 범용 등록 진입점."""
from __future__ import annotations

def get_full_hunt_registry(*args, **kwargs):
    """공개 코어에는 기본 대상 모듈을 포함하지 않는다."""
    return None
