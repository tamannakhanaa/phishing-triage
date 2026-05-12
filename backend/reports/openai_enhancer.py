"""
This module uses the OpenAI API to enhance phishing analysis reports.
"""
import os
from openai import OpenAI
import json
from typing import Dict, Any
import traceback

def enhance_report_with_openai(report_data: Dict[str, Any]) -> str:
    """
    Enhances a phishing analysis report with an executive summary from OpenAI.

    Args:
        report_data: A dictionary containing the analysis report.

    Returns:
        A string containing the AI-generated executive summary, or an empty string if failed.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    print(f"DEBUG (openai_enhancer): API Key loaded: {api_key[:5]}..." if api_key else "DEBUG (openai_enhancer): API Key not loaded.")
    if not api_key:
        print("OPENAI_API_KEY not found. Skipping report enhancement.")
        return ""

    client = OpenAI(api_key=api_key)

    # Sanitize the report data to be sent to the API
    prompt_data = report_data.copy()
    if "eml_analysis" in prompt_data and prompt_data.get("eml_analysis"):
        prompt_data["eml_analysis"].pop("full_content_cleaned", None)

    system_prompt = (
        "You are a Tier 3 Security Operations Center (SOC) analyst. "
        "Your task is to provide a concise, expert-level executive summary of a phishing analysis report. "
        "The summary should be formatted in Markdown and highlight the key findings, indicators of compromise (IOCs), "
        "and a final verdict on whether the URL/email is malicious. Be direct and use professional security terminology."
    )

    user_prompt = (
        "Based on the following JSON data from an automated analysis, please generate the executive summary:\n\n"
        f"```json\n{json.dumps(prompt_data, indent=2)}\n```"
    )

    try:
        print("Requesting report enhancement from OpenAI...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.5,
            max_tokens=500,
        )
        summary = response.choices[0].message.content
        print("Successfully received enhancement from OpenAI.")
        return summary.strip() if summary else ""
    except Exception as e:
        print(f"Error calling OpenAI API for report enhancement: {e}")
        traceback.print_exc()
        return ""
