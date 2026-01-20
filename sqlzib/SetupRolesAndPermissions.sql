USE SecureStudentRecords;
GO

-- Remove existing roles if present
IF DATABASE_PRINCIPAL_ID('AdminRole') IS NOT NULL
    DROP ROLE AdminRole;
IF DATABASE_PRINCIPAL_ID('InstructorRole') IS NOT NULL
    DROP ROLE InstructorRole;
IF DATABASE_PRINCIPAL_ID('TARole') IS NOT NULL
    DROP ROLE TARole;
IF DATABASE_PRINCIPAL_ID('StudentRole') IS NOT NULL
    DROP ROLE StudentRole;
IF DATABASE_PRINCIPAL_ID('GuestRole') IS NOT NULL
    DROP ROLE GuestRole;
GO

CREATE ROLE AdminRole;
CREATE ROLE InstructorRole;
CREATE ROLE TARole;
CREATE ROLE StudentRole;
CREATE ROLE GuestRole;
GO

-- Admin has complete access
GRANT SELECT, INSERT, UPDATE, DELETE ON Users TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Student TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Instructor TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Course TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Grades TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON Attendance TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON CourseEnrollment TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON TAAssignment TO AdminRole;
GRANT SELECT, INSERT, UPDATE, DELETE ON RoleRequests TO AdminRole;
GRANT SELECT, INSERT ON AuditLog TO AdminRole;
GO

-- Instructor permissions
GRANT SELECT ON Student TO InstructorRole;
GRANT SELECT ON Instructor TO InstructorRole;
GRANT SELECT ON Course TO InstructorRole;
GRANT SELECT, INSERT, UPDATE ON Grades TO InstructorRole;
GRANT SELECT, INSERT, UPDATE ON Attendance TO InstructorRole;
GRANT SELECT ON CourseEnrollment TO InstructorRole;
GRANT SELECT ON Users TO InstructorRole;
DENY DELETE ON Grades TO InstructorRole;
DENY DELETE ON Attendance TO InstructorRole;
GO

-- TA can manage attendance only
GRANT SELECT ON Student TO TARole;
GRANT SELECT ON Course TO TARole;
GRANT SELECT, INSERT, UPDATE ON Attendance TO TARole;
GRANT SELECT ON CourseEnrollment TO TARole;
GRANT SELECT ON TAAssignment TO TARole;
DENY SELECT ON Grades TO TARole;
DENY SELECT ON Instructor TO TARole;
DENY SELECT ON Users TO TARole;
GO

-- Students have limited read access
GRANT SELECT ON Course TO StudentRole;
DENY INSERT, UPDATE, DELETE ON Student TO StudentRole;
DENY INSERT, UPDATE, DELETE ON Grades TO StudentRole;
DENY INSERT, UPDATE, DELETE ON Attendance TO StudentRole;
DENY SELECT ON Users TO StudentRole;
DENY SELECT ON Instructor TO StudentRole;
GO

-- Guest can only view public course info
GRANT SELECT ON Course TO GuestRole;
DENY SELECT ON Student TO GuestRole;
DENY SELECT ON Instructor TO GuestRole;
DENY SELECT ON Grades TO GuestRole;
DENY SELECT ON Attendance TO GuestRole;
DENY SELECT ON Users TO GuestRole;
DENY SELECT ON CourseEnrollment TO GuestRole;
GO

PRINT 'Roles and permissions configured successfully.';
GO