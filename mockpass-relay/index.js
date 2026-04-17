const express = require('express');
const app = express();

app.get('/callback', (req, res) => {
    const { code, state } = req.query;

    console.log('Callback received:', { code, state });

    if (!code || !state || !state.includes('.')) {
        return res.status(400).send('Invalid callback');
    }

    const dotIndex = state.indexOf('.');
    const actualState = state.substring(0, dotIndex);
    const sessionDataKey = state.substring(dotIndex + 1);

    console.log('Redirecting with sessionDataKey:', sessionDataKey);

    const wso2Url = `https://localhost:9443/commonauth` +
        `?code=${encodeURIComponent(code)}` +
        `&state=${encodeURIComponent(actualState)}` +
        `&sessionDataKey=${encodeURIComponent(sessionDataKey)}`;

    console.log('WSO2 URL:', wso2Url);

    res.redirect(wso2Url);
});

app.listen(3000, () => {
    console.log('Relay running on http://localhost:3000');
});