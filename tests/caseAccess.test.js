process.env.NODE_ENV = 'test';

const { canViewCase, canModifyCase, isAdmin } = require('../utils/caseAccess');

describe('caseAccess', () => {
    const admin = { _id: 'admin1', role: 'ADMIN' };
    const officer = { _id: 'officer1', role: 'OFFICER' };
    const otherOfficer = { _id: 'officer2', role: 'OFFICER' };
    const teamMember = { _id: 'member1', role: 'OFFICER' };

    const caseWithAssignment = {
        assignedOfficer: 'officer1',
        assignedTeam: {
            members: [{ officer: 'member1' }]
        }
    };

    test('isAdmin identifies admin role', () => {
        expect(isAdmin(admin)).toBe(true);
        expect(isAdmin(officer)).toBe(false);
    });

    test('canModifyCase allows assigned officer and admin only', async () => {
        expect(await canModifyCase(admin, caseWithAssignment)).toBe(true);
        expect(await canModifyCase(officer, caseWithAssignment)).toBe(true);
        expect(await canModifyCase(otherOfficer, caseWithAssignment)).toBe(false);
        expect(await canModifyCase(teamMember, caseWithAssignment)).toBe(false);
    });

    test('canViewCase allows team members to read', async () => {
        expect(await canViewCase(teamMember, caseWithAssignment)).toBe(true);
        expect(await canViewCase(otherOfficer, caseWithAssignment)).toBe(false);
    });
});
