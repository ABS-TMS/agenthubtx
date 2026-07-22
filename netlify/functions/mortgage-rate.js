// Netlify Function: mortgage-rate
// Thin server-side proxy for the api-ninjas mortgage rate endpoint, so the
// real API key never ships to the browser (it was previously hardcoded
// directly in dashboard.html, community.html, and index.html).

exports.handler = async () => {
  const API_KEY = process.env.MORTGAGE_API_KEY;

  try {
    const resp = await fetch('https://api.api-ninjas.com/v2/mortgagerate', {
      headers: { 'X-Api-Key': API_KEY },
    });
    const data = await resp.json();
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600' },
      body: JSON.stringify(data),
    };
  } catch (err) {
    console.error('mortgage-rate error:', err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Could not fetch mortgage rate' }) };
  }
};
