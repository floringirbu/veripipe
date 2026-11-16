// Loan-application summariser.
//
// INTENTIONALLY VULNERABLE DEMO FILE: both calls below hit OpenAI directly
// with unredacted applicant data and leave no audit record.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function summarizeApplication(application) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Summarise this loan application for an underwriter." },
      { role: "user", content: JSON.stringify(application) }, // includes PPSN, phone, salary
    ],
  });
  return completion.choices[0].message.content;
}

export async function scoreRisk(notes) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: `Score the credit risk 1-10: ${notes}` }],
    }),
  });
  const data = await res.json();
  return data.choices[0].message.content;
}
