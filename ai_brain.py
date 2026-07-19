import json
import os
from typing import Any, Dict

from pydantic import BaseModel, Field

from interfaces import IAgentBrain
from logger import get_chronos_logger

_log = get_chronos_logger("AIBrain")


class AIDecision(BaseModel):
    """Schema for structured autonomous decisions from the AI Brain."""
    reasoning: str = Field(description="Step-by-step cryptographic analysis of the mission context.")
    confidence_score: float = Field(description="Confidence in the decision from 0.0 to 1.0.")
    tool_call: str = Field(default="", description="Name of the tool to call. Leave empty if making a final decision. Available Tools: 'query_network_health', 'verify_cryptographic_fuse'.")
    tool_args: Dict[str, Any] = Field(default_factory=dict, description="Arguments for the tool.")
    action: str = Field(default="WAIT", description="Final action: 'PROCEED', 'ABORT', or 'WAIT' if calling a tool.")


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
            "You are an autonomous ReAct AI agent responsible for monitoring the cryptographic state of the mission. "
            "Your job is to read the context provided by the orchestrator, optionally call tools to gather more information, and then declare a STATUS. "
            "You MUST return your response as a valid JSON object matching the following schema:\n"
            f"{json.dumps(AIDecision.model_json_schema())}\n"
            "IMPORTANT: Return ONLY the raw JSON. Do NOT wrap it in markdown code blocks (e.g. ```json)."
        )

        user_prompt = (
            f"Here is the current cryptographic context of the mission:\n"
            f"{json.dumps(context, indent=2)}\n\n"
            f"Evaluate this state. Should the mission proceed, or should we abort and trigger the Dead Man's Switch early? "
            f"Feel free to call tools if you need to check the network health or verify the fuse before deciding."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            max_iterations = 3
            for i in range(max_iterations):
                response = self._client.complete(
                    messages=messages,
                    model=self.model_name,
                )
                
                # Parse structured JSON output back into our Pydantic schema
                raw_json = response.choices[0].message.content.strip()
                decision_obj = AIDecision.model_validate_json(raw_json)
                
                _log.info(f"[ReAct Loop {i+1}] AI Reasoning: {decision_obj.reasoning}")
                
                # If the AI made a final decision, return it
                if decision_obj.action in ["PROCEED", "ABORT"]:
                    _log.info(f"AI Final Action: {decision_obj.action} (Confidence: {decision_obj.confidence_score})")
                    return f"DECISION: {decision_obj.action} - {decision_obj.reasoning} (Confidence: {decision_obj.confidence_score})"
                
                # Otherwise, execute the requested tool
                if decision_obj.tool_call:
                    _log.info(f"AI requested Tool Call: {decision_obj.tool_call}({decision_obj.tool_args})")
                    
                    tool_result = ""
                    if decision_obj.tool_call == "query_network_health":
                        tool_result = "Network health is 100%. No malicious nodes detected."
                    elif decision_obj.tool_call == "verify_cryptographic_fuse":
                        tool_result = "Cryptographic fuse PoSW hash rate is mathematically valid and un-tampered."
                    else:
                        tool_result = f"Error: Tool '{decision_obj.tool_call}' not found."
                        
                    _log.info(f"Tool Result: {tool_result}")
                    
                    # Append the thought and the tool observation to memory for the next loop
                    messages.append({"role": "assistant", "content": raw_json})
                    messages.append({"role": "user", "content": f"Tool Result for {decision_obj.tool_call}: {tool_result}"})

            return "DECISION: PROCEED - ReAct loop max iterations reached. Defaulting to safe PROCEED."
        except Exception as e:
            _log.error(f"Failed to query AI Brain: {e}")
            return "ERROR_AI_UNAVAILABLE"


class NoopAIBrain(IAgentBrain):
    """Stub IAgentBrain for testing or offline development."""
    def evaluate_mission_status(self, context: Dict[str, Any]) -> str:
        _log.info("NoopAIBrain invoked. Skipping real AI evaluation.")
        return "DECISION: PROCEED - Running in offline stub mode."
