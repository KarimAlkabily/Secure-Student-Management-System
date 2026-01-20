USE SecureStudentRecords;
GO

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Users')
BEGIN
    RAISERROR('ERROR: Users table does not exist! Please run 02_CreateTables.sql first.', 16, 1);
    RETURN;
END

IF NOT EXISTS (
    SELECT 1 FROM sys.columns 
    WHERE object_id = OBJECT_ID('Users') AND name = 'PasswordEncrypted'
)
BEGIN
    PRINT 'Adding PasswordEncrypted column to Users table...';
    
    DECLARE @UserCount INT;
    SELECT @UserCount = COUNT(*) FROM Users;
    
    IF @UserCount > 0
    BEGIN
        PRINT 'WARNING: Users table contains ' + CAST(@UserCount AS VARCHAR(10)) + ' existing user(s).';
        PRINT 'These users will need to be re-registered or have passwords reset.';
    END
    
    ALTER TABLE Users ADD PasswordEncrypted VARBINARY(MAX) NULL;
    
    IF @UserCount > 0
    BEGIN
        IF EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = 'StudentRecordsKey')
        BEGIN
            OPEN SYMMETRIC KEY StudentRecordsKey
            DECRYPTION BY CERTIFICATE StudentRecordsCert;
            
            UPDATE Users 
            SET PasswordEncrypted = EncryptByKey(Key_GUID('StudentRecordsKey'), 'TEMP_RESET_REQUIRED')
            WHERE PasswordEncrypted IS NULL;
            
            CLOSE SYMMETRIC KEY StudentRecordsKey;
        END
        ELSE
        BEGIN
            UPDATE Users 
            SET PasswordEncrypted = 0x00000000000000000000000000000000
            WHERE PasswordEncrypted IS NULL;
            PRINT 'WARNING: Encryption key not found. Existing users will need to be re-registered.';
        END
    END
    
    ALTER TABLE Users ALTER COLUMN PasswordEncrypted VARBINARY(MAX) NOT NULL;
    
    PRINT 'PasswordEncrypted column added successfully.';
END
GO

CREATE OR ALTER PROCEDURE sp_RegisterUser
    @Username NVARCHAR(50),
    @Password NVARCHAR(100),
    @Role NVARCHAR(20),
    @ClearanceLevel INT,
    @CreatedByAdminID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        IF @Username IS NULL OR LEN(LTRIM(RTRIM(@Username))) = 0
        BEGIN
            RAISERROR('Username is required', 16, 1);
            RETURN;
        END
        
        IF @Password IS NULL OR LEN(@Password) < 6
        BEGIN
            RAISERROR('Password must be at least 6 characters long', 16, 1);
            RETURN;
        END
        
        IF @Role NOT IN ('Admin', 'Instructor', 'TA', 'Student', 'Guest')
        BEGIN
            RAISERROR('Invalid role specified', 16, 1);
            RETURN;
        END
        
        IF @ClearanceLevel < 1 OR @ClearanceLevel > 4
        BEGIN
            RAISERROR('Clearance level must be between 1 and 4', 16, 1);
            RETURN;
        END
        
        IF (@Role = 'Admin' AND @ClearanceLevel != 4) OR
           (@Role = 'Instructor' AND @ClearanceLevel < 3) OR
           (@Role = 'TA' AND @ClearanceLevel < 2) OR
           (@Role = 'Student' AND @ClearanceLevel < 1) OR
           (@Role = 'Guest' AND @ClearanceLevel != 1)
        BEGIN
            RAISERROR('Role and clearance level are not compatible', 16, 1);
            RETURN;
        END
        
        IF EXISTS (SELECT 1 FROM Users WHERE Username = @Username)
        BEGIN
            RAISERROR('Username already exists', 16, 1);
            RETURN;
        END
        
        IF @CreatedByAdminID IS NOT NULL
        BEGIN
            DECLARE @AdminRole NVARCHAR(20);
            SELECT @AdminRole = Role FROM Users WHERE UserID = @CreatedByAdminID;
            
            IF @AdminRole != 'Admin'
            BEGIN
                RAISERROR('Only Admin can create users', 16, 1);
                RETURN;
            END
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        DECLARE @PasswordEncrypted VARBINARY(MAX) = EncryptByKey(Key_GUID('StudentRecordsKey'), @Password);
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO Users (Username, PasswordEncrypted, Role, ClearanceLevel)
        VALUES (@Username, @PasswordEncrypted, @Role, @ClearanceLevel);
        
        INSERT INTO AuditLog (Username, Action, TableAffected, RecordID, ActionDate)
        VALUES (@Username, 'User Registration', 'Users', SCOPE_IDENTITY(), GETDATE());
        
        SELECT 'Success' AS Result, SCOPE_IDENTITY() AS UserID;
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        INSERT INTO AuditLog (Username, Action, Success, ErrorMessage)
        VALUES (@Username, 'User Registration Failed', 0, ERROR_MESSAGE());
        
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_Login
    @Username NVARCHAR(50),
    @Password NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @UserID INT;
    DECLARE @StoredPasswordEncrypted VARBINARY(MAX);
    DECLARE @Role NVARCHAR(20);
    DECLARE @ClearanceLevel INT;
    DECLARE @IsActive BIT;
    
    SELECT 
        @UserID = UserID,
        @StoredPasswordEncrypted = PasswordEncrypted,
        @Role = Role,
        @ClearanceLevel = ClearanceLevel,
        @IsActive = IsActive
    FROM Users
    WHERE Username = @Username;
    
    IF @UserID IS NULL
    BEGIN
        INSERT INTO AuditLog (Username, Action, Success, ErrorMessage)
        VALUES (@Username, 'Login Failed', 0, 'User not found');
        
        SELECT 'Error' AS Result, 'Invalid credentials' AS Message;
        RETURN;
    END
    
    IF @IsActive = 0
    BEGIN
        INSERT INTO AuditLog (UserID, Username, Action, Success, ErrorMessage)
        VALUES (@UserID, @Username, 'Login Failed', 0, 'Account disabled');
        
        SELECT 'Error' AS Result, 'Account is disabled' AS Message;
        RETURN;
    END
    
    OPEN SYMMETRIC KEY StudentRecordsKey
    DECRYPTION BY CERTIFICATE StudentRecordsCert;
    
    DECLARE @DecryptedPassword NVARCHAR(100) = CONVERT(NVARCHAR(100), DecryptByKey(@StoredPasswordEncrypted));
    
    CLOSE SYMMETRIC KEY StudentRecordsKey;
    
    IF @Password = @DecryptedPassword
    BEGIN
        UPDATE Users SET LastLogin = GETDATE() WHERE UserID = @UserID;
        
        INSERT INTO AuditLog (UserID, Username, Action, ActionDate)
        VALUES (@UserID, @Username, 'Login Successful', GETDATE());
        
        SELECT 
            'Success' AS Result,
            @UserID AS UserID,
            @Username AS Username,
            @Role AS Role,
            @ClearanceLevel AS ClearanceLevel;
    END
    ELSE
    BEGIN
        INSERT INTO AuditLog (UserID, Username, Action, Success, ErrorMessage)
        VALUES (@UserID, @Username, 'Login Failed', 0, 'Invalid password');
        
        SELECT 'Error' AS Result, 'Invalid credentials' AS Message;
    END
END
GO

CREATE OR ALTER PROCEDURE sp_AddStudent
    @FullName NVARCHAR(100),
    @Email NVARCHAR(100),
    @Phone NVARCHAR(20),
    @DOB DATE,
    @Department NVARCHAR(50),
    @UserID INT = NULL,
    @RequestingUserID INT,
    @RequestingUserClearance INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        IF @RequesterRole NOT IN ('Admin', 'Instructor')
        BEGIN
            RAISERROR('Access Denied: Insufficient privileges', 16, 1);
            RETURN;
        END
        
        IF @RequestingUserClearance < 2
        BEGIN
            RAISERROR('MLS Violation: Cannot write to Confidential level', 16, 1);
            RETURN;
        END
        
        IF @FullName IS NULL OR LEN(LTRIM(RTRIM(@FullName))) = 0
        BEGIN
            RAISERROR('Full name is required', 16, 1);
            RETURN;
        END
        
        IF @Email IS NULL OR LEN(LTRIM(RTRIM(@Email))) = 0
        BEGIN
            RAISERROR('Email is required', 16, 1);
            RETURN;
        END
        
        IF @DOB IS NULL
        BEGIN
            RAISERROR('Date of birth is required', 16, 1);
            RETURN;
        END
        
        IF @Department IS NULL OR LEN(LTRIM(RTRIM(@Department))) = 0
        BEGIN
            RAISERROR('Department is required', 16, 1);
            RETURN;
        END
        
        IF EXISTS (SELECT 1 FROM Student WHERE Email = @Email)
        BEGIN
            RAISERROR('Email already exists', 16, 1);
            RETURN;
        END
        
        IF @UserID IS NOT NULL
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM Users WHERE UserID = @UserID)
            BEGIN
                RAISERROR('User ID not found', 16, 1);
                RETURN;
            END
            
            IF EXISTS (SELECT 1 FROM Student WHERE UserID = @UserID)
            BEGIN
                RAISERROR('User ID is already linked to another student', 16, 1);
                RETURN;
            END
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        DECLARE @PhoneEncrypted VARBINARY(256) = EncryptByKey(Key_GUID('StudentRecordsKey'), @Phone);
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO Student (FullName, Email, PhoneEncrypted, DOB, Department, UserID)
        VALUES (@FullName, @Email, @PhoneEncrypted, @DOB, @Department, @UserID);
        
        DECLARE @NewStudentID INT = SCOPE_IDENTITY();
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        UPDATE Student 
        SET StudentIDEncrypted = EncryptByKey(Key_GUID('StudentRecordsKey'), CAST(@NewStudentID AS VARCHAR(10)))
        WHERE StudentID = @NewStudentID;
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@RequestingUserID, 'Add Student', 'Student', @NewStudentID);
        
        SELECT 'Success' AS Result, @NewStudentID AS StudentID;
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        INSERT INTO AuditLog (UserID, Action, Success, ErrorMessage)
        VALUES (@RequestingUserID, 'Add Student Failed', 0, ERROR_MESSAGE());
        
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_ViewStudentProfile
    @StudentID INT,
    @RequestingUserID INT,
    @RequestingUserClearance INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @DataClassification INT;
        SELECT @DataClassification = ClassificationLevel FROM Student WHERE StudentID = @StudentID;
        
        IF @RequestingUserClearance < @DataClassification
        BEGIN
            RAISERROR('MLS Violation: Cannot read higher classification', 16, 1);
            RETURN;
        END
        
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        IF @RequesterRole = 'Student'
        BEGIN
            DECLARE @LinkedUserID INT;
            SELECT @LinkedUserID = UserID FROM Student WHERE StudentID = @StudentID;
            
            IF @LinkedUserID != @RequestingUserID
            BEGIN
                RAISERROR('Access Denied: Can only view own profile', 16, 1);
                RETURN;
            END
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        SELECT 
            StudentID,
            FullName,
            Email,
            CASE 
                WHEN PhoneEncrypted IS NULL THEN NULL
                ELSE CAST(DecryptByKey(PhoneEncrypted) AS NVARCHAR(20))
            END AS Phone,
            DOB,
            Department,
            ClearanceLevel
        FROM Student
        WHERE StudentID = @StudentID;
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@RequestingUserID, 'View Student Profile', 'Student', @StudentID);
        
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_EnterGrade
    @StudentID INT,
    @CourseID INT,
    @GradeValue DECIMAL(5,2),
    @RequestingUserID INT,
    @RequestingUserClearance INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        IF @RequesterRole NOT IN ('Admin', 'Instructor')
        BEGIN
            RAISERROR('Access Denied: Only Instructors and Admins can enter grades', 16, 1);
            RETURN;
        END
        
        IF @RequestingUserClearance < 3
        BEGIN
            RAISERROR('MLS Violation: Cannot write to Secret level', 16, 1);
            RETURN;
        END
        
        IF NOT EXISTS (SELECT 1 FROM Student WHERE StudentID = @StudentID)
        BEGIN
            RAISERROR('Student not found', 16, 1);
            RETURN;
        END
        
        IF NOT EXISTS (SELECT 1 FROM Course WHERE CourseID = @CourseID)
        BEGIN
            RAISERROR('Course not found', 16, 1);
            RETURN;
        END
        
        IF NOT EXISTS (SELECT 1 FROM CourseEnrollment WHERE StudentID = @StudentID AND CourseID = @CourseID)
        BEGIN
            RAISERROR('Student is not enrolled in this course', 16, 1);
            RETURN;
        END
        
        IF @GradeValue < 0 OR @GradeValue > 100
        BEGIN
            RAISERROR('Grade value must be between 0 and 100', 16, 1);
            RETURN;
        END
        
        DECLARE @InstructorID INT;
        SELECT @InstructorID = InstructorID FROM Instructor WHERE UserID = @RequestingUserID;
        
        IF @InstructorID IS NULL AND @RequesterRole != 'Admin'
        BEGIN
            RAISERROR('Instructor record not found', 16, 1);
            RETURN;
        END
        
        IF @RequesterRole = 'Instructor'
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM Course WHERE CourseID = @CourseID AND InstructorID = @InstructorID)
            BEGIN
                RAISERROR('Access Denied: You do not teach this course', 16, 1);
                RETURN;
            END
        END
        
        IF @RequesterRole = 'Admin' AND @InstructorID IS NULL
        BEGIN
            SELECT @InstructorID = InstructorID FROM Course WHERE CourseID = @CourseID;
            
            IF @InstructorID IS NULL
            BEGIN
                SELECT TOP 1 @InstructorID = InstructorID FROM Instructor ORDER BY InstructorID;
                
                IF @InstructorID IS NULL
                BEGIN
                    RAISERROR('Cannot enter grade: No instructors exist in the system', 16, 1);
                    RETURN;
                END
            END
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        DECLARE @StudentIDEncrypted VARBINARY(256) = EncryptByKey(Key_GUID('StudentRecordsKey'), CAST(@StudentID AS VARCHAR(10)));
        DECLARE @GradeValueEncrypted VARBINARY(256) = EncryptByKey(Key_GUID('StudentRecordsKey'), CAST(@GradeValue AS VARCHAR(10)));
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO Grades (StudentIDEncrypted, CourseID, GradeValueEncrypted, EnteredByInstructorID)
        VALUES (@StudentIDEncrypted, @CourseID, @GradeValueEncrypted, @InstructorID);
        
        DECLARE @GradeID INT = SCOPE_IDENTITY();
        
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@RequestingUserID, 'Enter Grade', 'Grades', @GradeID);
        
        SELECT 'Success' AS Result, @GradeID AS GradeID;
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        INSERT INTO AuditLog (UserID, Action, Success, ErrorMessage)
        VALUES (@RequestingUserID, 'Enter Grade Failed', 0, ERROR_MESSAGE());
        
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_ViewGrades
    @StudentID INT = NULL,
    @CourseID INT = NULL,
    @RequestingUserID INT,
    @RequestingUserClearance INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        IF @RequestingUserClearance < 3
        BEGIN
            RAISERROR('MLS Violation: Cannot read Secret level data', 16, 1);
            RETURN;
        END
        
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        IF @RequesterRole NOT IN ('Admin', 'Instructor')
        BEGIN
            RAISERROR('Access Denied: Only Instructors and Admins can view all grades', 16, 1);
            RETURN;
        END
        
        DECLARE @InstructorID INT;
        IF @RequesterRole = 'Instructor'
        BEGIN
            SELECT @InstructorID = InstructorID FROM Instructor WHERE UserID = @RequestingUserID;
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        SELECT 
            g.GradeID,
            CAST(CAST(DecryptByKey(g.StudentIDEncrypted) AS VARCHAR(10)) AS INT) AS StudentID,
            s.FullName AS StudentName,
            g.CourseID,
            c.CourseName,
            CAST(CAST(DecryptByKey(g.GradeValueEncrypted) AS VARCHAR(10)) AS DECIMAL(5,2)) AS GradeValue,
            g.DateEntered,
            i.FullName AS EnteredBy
        FROM Grades g
        INNER JOIN Course c ON g.CourseID = c.CourseID
        INNER JOIN Instructor i ON g.EnteredByInstructorID = i.InstructorID
        LEFT JOIN Student s ON s.StudentID = CAST(CAST(DecryptByKey(g.StudentIDEncrypted) AS VARCHAR(10)) AS INT)
        WHERE 
            (@StudentID IS NULL OR CAST(CAST(DecryptByKey(g.StudentIDEncrypted) AS VARCHAR(10)) AS INT) = @StudentID)
            AND (@CourseID IS NULL OR g.CourseID = @CourseID)
            AND (@RequesterRole = 'Admin' OR c.InstructorID = @InstructorID);
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO AuditLog (UserID, Action, TableAffected)
        VALUES (@RequestingUserID, 'View Grades', 'Grades');
        
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_StudentViewOwnGrades
    @RequestingUserID INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @StudentID INT;
        SELECT @StudentID = StudentID FROM Student WHERE UserID = @RequestingUserID;
        
        IF @StudentID IS NULL
        BEGIN
            RAISERROR('Student record not found', 16, 1);
            RETURN;
        END
        
        OPEN SYMMETRIC KEY StudentRecordsKey
        DECRYPTION BY CERTIFICATE StudentRecordsCert;
        
        SELECT 
            c.CourseName,
            CAST(CAST(DecryptByKey(g.GradeValueEncrypted) AS VARCHAR(10)) AS DECIMAL(5,2)) AS GradeValue,
            g.DateEntered
        FROM Grades g
        INNER JOIN Course c ON g.CourseID = c.CourseID
        WHERE CAST(CAST(DecryptByKey(g.StudentIDEncrypted) AS VARCHAR(10)) AS INT) = @StudentID;
        
        CLOSE SYMMETRIC KEY StudentRecordsKey;
        
        INSERT INTO AuditLog (UserID, Action, TableAffected)
        VALUES (@RequestingUserID, 'View Own Grades', 'Grades');
        
    END TRY
    BEGIN CATCH
        IF (SELECT COUNT(*) FROM sys.openkeys WHERE key_name = 'StudentRecordsKey') > 0
            CLOSE SYMMETRIC KEY StudentRecordsKey;
            
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

PRINT 'Authentication and student/grade procedures created successfully.';
GO