// tests/sanitizeInput.test.js
// Unit tests for middleware/sanitizeInput.js
// Tests XSS sanitization and NoSQL injection prevention

process.env.SKIP_DB = 'true';

const sanitizeInput = require('../middleware/sanitizeInput');
const { queryText, pickAllowed, sanitizeContainer } = require('../middleware/sanitizeInput');

describe('sanitizeInput Middleware Unit Tests', () => {
    test('strips HTML tags and script injections from req.body strings', () => {
        const req = {
            body: {
                title: 'Incident <script>alert("XSS")</script>Report',
                description: '<img src=x onerror=alert(1)>Wild elephant spotted'
            }
        };
        const next = jest.fn();

        sanitizeInput(req, {}, next);

        expect(req.body.title).toBe('Incident Report');
        expect(req.body.description).toBe('Wild elephant spotted');
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('preserves password fields unchanged without stripping characters', () => {
        const req = {
            body: {
                password: 'P@$$w0rd<with>symbols&!',
                confirmPassword: 'P@$$w0rd<with>symbols&!',
                username: '<b>user1</b>'
            }
        };
        const next = jest.fn();

        sanitizeInput(req, {}, next);

        expect(req.body.password).toBe('P@$$w0rd<with>symbols&!');
        expect(req.body.confirmPassword).toBe('P@$$w0rd<with>symbols&!');
        expect(req.body.username).toBe('user1');
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('strips dangerous MongoDB operator keys ($gt, $ne, etc.) preventing NoSQL injection', () => {
        const req = {
            body: {
                username: 'admin',
                $where: 'sleep(5000)',
                filter: {
                    $gt: '',
                    validField: 'safe'
                }
            }
        };
        const next = jest.fn();

        sanitizeInput(req, {}, next);

        expect(req.body.$where).toBeUndefined();
        expect(req.body.filter.$gt).toBeUndefined();
        expect(req.body.filter.validField).toBe('safe');
        expect(req.body.username).toBe('admin');
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('prevents prototype pollution keys (__proto__, constructor, prototype)', () => {
        const req = {
            body: JSON.parse('{"__proto__": {"admin": true}, "constructor": "bad", "prototype": "bad", "name": "Clean"}')
        };
        const next = jest.fn();

        sanitizeInput(req, {}, next);

        expect(Object.prototype.hasOwnProperty.call(req.body, '__proto__')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(req.body, 'constructor')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(req.body, 'prototype')).toBe(false);
        expect(req.body.name).toBe('Clean');
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('sanitizes query parameters and removes operators from req.query', () => {
        const req = {
            query: {
                search: '<script>evil()</script>tigers',
                $regex: '.*',
                page: '1',
                filterObj: { $ne: null }
            }
        };
        const next = jest.fn();

        sanitizeInput(req, {}, next);

        expect(req.query.search).toBe('tigers');
        expect(req.query.$regex).toBeUndefined();
        expect(req.query.page).toBe('1');
        expect(req.query.filterObj).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('queryText helper trims strings or returns empty string for non-strings', () => {
        expect(queryText('  wildlife  ')).toBe('wildlife');
        expect(queryText(123)).toBe('');
        expect(queryText(null)).toBe('');
        expect(queryText({ $gt: '' })).toBe('');
    });

    test('pickAllowed helper only extracts allowed properties from source object', () => {
        const source = { name: 'Park A', location: 'North', extra: 'drop_me', $bad: 1 };
        const result = pickAllowed(source, ['name', 'location']);

        expect(result).toEqual({ name: 'Park A', location: 'North' });
        expect(result.extra).toBeUndefined();
        expect(result.$bad).toBeUndefined();
    });
});
