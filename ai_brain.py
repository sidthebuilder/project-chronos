import json
import os
import sys
from typing import Any, Dict

from pydantic import BaseModel, Field

from interfaces import IAgentBrain
from logger import get_chronos_logger

_log = get_chronos_logger("AIBrain")

class AIDecision(BaseModel):
    """Schema for structured autonomous decisions from the AI Brain."""
    reasoning: str = Field(description="Step-by-step cryptographic analysis of the mission context.")
    confidence_score: float = Field(description="Confidence in the decision from 0.0 to 1.0.")
    action: str = Field(description="The final action to take. Must be exactly 'PROCEED' or 'ABORT'.")

class GitHubModelsBrain(IAgentBrain):
    """Concrete implementation of IAgentBrain using GitHub Models (GPT-4o).
    
    This brain connects to the GitHub Models inference endpoint and evaluates
    the agent's cryptographic state to make an autonomous decision.
    """

    def __init__(self, model_name: str = "gpt-4o"):
        self.model_name = model_name
        self.endpoint = "https://models.github.ai/inference"
        
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            _log.warning(
                "GITHUB_TOKEN environment variable not set. "
                "The AI Brain will run in offline mode (No-op)."
            )
            self._client = None
            return

        try:
            from azure.ai.inference import ChatCompletionsClient
            from azure.core.credentials import AzureKeyCredential
            self._client = ChatCompletionsClient(
                endpoint=self.endpoint,
                credential=AzureKeyCredential(token),
            )
        except ImportError:
            _log.error("Failed to import azure-ai-inference or azure-core. Is it installed?")
            self._client = None

    def evaluate_mission_status(self, context: Dict[str, Any]) -> str:
        """Query GPT-4o with the mission context to make an autonomous decision."""
        if not self._client:
            _log.warning("AI Brain is offline. Returning default SAFE status.")
            return "DEFAULT_SAFE"

        _log.info(f"Connecting to {self.model_name} at GitHub Models for autonomous evaluation...")
        
        system_prompt = (
            "You are the advanced cryptographic brain of Project Chronos. "
            "You are an autonomous AI agent responsible for monitoring the cryptographic state of the mission. "
            "Your job is to read the context provided by the orchestrator and declare a STATUS. "
            "You MUST return your response as a valid JSON object matching the following schema:\n"
            f"{json.dumps(AIDecision.model_json_schema())}\n"
            "IMPORTANT: Return ONLY the raw JSON. Do NOT wrap it in markdown code blocks (e.g. ```json)."
        )

        user_prompt = (
            f"Here is the current cryptographic context of the mission:\n"
            f"{json.dumps(context, indent=2)}\n\n"
            f"Evaluate this state. Should the mission proceed, or should we abort and trigger the Dead Man's Switch early?"
        )

        try:
            response = self._client.complete(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                model=self.model_name,
            )
            
            # Parse structured JSON output back into our Pydantic schema
            raw_json = response.choices[0].message.content.strip()
            decision_obj = AIDecision.model_validate_json(raw_json)
            
            # Log the transparent reasoning chain
            _log.info(f"AI Reasoning: {decision_obj.reasoning}")
            _log.info(f"AI Confidence Score: {decision_obj.confidence_score}")
            _log.info(f"AI Final Action: {decision_obj.action}")
            
            return f"DECISION: {decision_obj.action} - {decision_obj.reasoning} (Confidence: {decision_obj.confidence_score})"
        except Exception as e:
            _log.error(f"Failed to query AI Brain: {e}")
            return "ERROR_AI_UNAVAILABLE"

class NoopAIBrain(IAgentBrain):
    """Stub IAgentBrain for testing or offline development."""
    def evaluate_mission_status(self, context: Dict[str, Any]) -> str:
        _log.info("NoopAIBrain invoked. Skipping real AI evaluation.")
        return "DECISION: PROCEED - Running in offline stub mode."
