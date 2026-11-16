"""Customer-support assistant for a retail bank.

INTENTIONALLY VULNERABLE DEMO FILE: every LLM call below goes straight to
OpenAI with raw customer data - no redaction, no policy, no audit trail.
"""
import os

import requests
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def answer_ticket(customer_email: str, iban: str, question: str) -> str:
    """Drafts a reply. Sends the customer's email address and IBAN to the model verbatim."""
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful banking support agent."},
            {"role": "user", "content": f"Customer {customer_email} (IBAN {iban}) asks: {question}"},
        ],
    )
    return response.choices[0].message.content


def classify_complaint(text: str) -> str:
    """Legacy path that calls the REST API by hand."""
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY')}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": f"Classify this complaint: {text}"}],
        },
        timeout=30,
    )
    return resp.json()["choices"][0]["message"]["content"]


if __name__ == "__main__":
    print(answer_ticket("aoife.byrne@example.ie", "IE29 AIBK 9311 5212 3456 78", "Why was my card declined?"))
