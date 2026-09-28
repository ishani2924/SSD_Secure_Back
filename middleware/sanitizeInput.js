const xss = require('xss');

// Plain-text API. Drop every HTML tag, including the insides of script and style.
const stripHtml = new xss.FilterXSS({
    whiteList: {},
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
});

// Passwords are hashed and never rendered. Stripping characters would change the password.
const SKIP_HTML_CLEAN = new Set([
    'password',
    'currentPassword',
    'newPassword',
    'confirmPassword'
]);

function isDangerousKey(key) {
    return (
        key.startsWith('$') ||
        key.includes('.') ||
        key === '__proto__' ||
        key === 'constructor' ||
        key === 'prototype'
    );
}

function isPlainObject(value) {
    return Object.prototype.toString.call(value) === '[object Object]';
}

function cleanText(value) {
    return stripHtml.process(value);
}

function sanitizeValue(value, key) {
    if (typeof value === 'string') {
        if (key && SKIP_HTML_CLEAN.has(key)) return value;
        return cleanText(value);
    }

    if (Array.isArray(value)) {
        return value.map((item) => sanitizeValue(item, key));
    }

    if (!isPlainObject(value)) return value;

    const clean = {};
    for (const [childKey, childValue] of Object.entries(value)) {
        if (isDangerousKey(childKey)) continue;
        clean[childKey] = sanitizeValue(childValue, childKey);
    }
    return clean;
}

function sanitizeContainer(container) {
    if (Array.isArray(container)) {
        for (let i = 0; i < container.length; i += 1) {
            container[i] = sanitizeValue(container[i]);
        }
        return;
    }

    if (!isPlainObject(container)) return;

    for (const key of Object.keys(container)) {
        if (isDangerousKey(key)) {
            delete container[key];
            continue;
        }
        container[key] = sanitizeValue(container[key], key);
    }
}

// Query values must be text. An object here would be a MongoDB operator.
function sanitizeQuery(query) {
    if (!isPlainObject(query)) return;

    for (const key of Object.keys(query)) {
        if (isDangerousKey(key)) {
            delete query[key];
            continue;
        }

        const value = query[key];
        if (typeof value === 'string') {
            query[key] = cleanText(value);
        } else if (Array.isArray(value)) {
            query[key] = value
                .filter((item) => typeof item === 'string')
                .map((item) => cleanText(item));
        } else {
            delete query[key];
        }
    }
}

function sanitizeInput(req, _res, next) {
    if (req.body) sanitizeContainer(req.body);
    if (req.query) sanitizeQuery(req.query);
    if (req.params) sanitizeContainer(req.params);
    next();
}

function queryText(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function pickAllowed(source, keys) {
    const updates = {};
    if (!isPlainObject(source)) return updates;

    for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            updates[key] = source[key];
        }
    }
    return updates;
}

module.exports = sanitizeInput;
module.exports.queryText = queryText;
module.exports.pickAllowed = pickAllowed;
module.exports.sanitizeContainer = sanitizeContainer;
