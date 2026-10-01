from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    raw_email: str = Field(min_length=1, strict=True)
    chain_limit: int = Field(default=50, gt=0, strict=True)

    @field_validator("raw_email")
    @classmethod
    def nonempty(cls, value):
        if not value.strip():
            raise ValueError("邮件内容为空。")
        return value
