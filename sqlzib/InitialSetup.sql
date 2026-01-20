USE master;
GO

IF EXISTS (SELECT name FROM sys.databases WHERE name = 'SecureStudentRecords')
BEGIN
    ALTER DATABASE SecureStudentRecords SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SecureStudentRecords;
END
GO

CREATE DATABASE SecureStudentRecords;
GO

USE SecureStudentRecords;
GO

-- Setup encryption for sensitive data protection
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongMasterKey@2025!';
GO

CREATE CERTIFICATE StudentRecordsCert
    WITH SUBJECT = 'Certificate for Student Records Encryption';
GO

CREATE SYMMETRIC KEY StudentRecordsKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE StudentRecordsCert;
GO

PRINT 'Database setup completed successfully.';
GO