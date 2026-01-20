USE SecureStudentRecords;
GO


--  Instructors
IF NOT EXISTS (SELECT 1 FROM Instructor WHERE Email = 'john.doe@university.edu')
BEGIN
    INSERT INTO Instructor (FullName, Email, Department, ClearanceLevel, ClassificationLevel)
    VALUES 
        ('Dr. John Doe', 'john.doe@university.edu', 'Computer Science', 3, 2),
        ('Dr. Jane Smith', 'jane.smith@university.edu', 'Mathematics', 3, 2);
    PRINT 'Instructors added successfully.';
END
GO

--  Courses
IF NOT EXISTS (SELECT 1 FROM Course WHERE CourseName = 'Database Security')
BEGIN
    INSERT INTO Course (CourseName, Description, PublicInfo, InstructorID, ClassificationLevel)
    VALUES 
        ('Database Security', 'Advanced course on database security concepts', 'Learn database security fundamentals', 1, 1),
        ('Data Structures', 'Introduction to data structures and algorithms', 'Essential programming concepts', 1, 1),
        ('Calculus I', 'Single variable calculus', 'Mathematics foundation course', 2, 1);
    PRINT 'Courses added successfully.';
END
GO

-- ============ Stored Procedures  ============

CREATE OR ALTER PROCEDURE sp_RecordAttendance
    @StudentID INT,
    @CourseID INT,
    @Status BIT,
    @RequestingUserID INT,
    @RequestingUserClearance INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        -- فقط Instructor و TA و Admin 
        IF @RequesterRole NOT IN ('Admin', 'Instructor', 'TA')
        BEGIN
            RAISERROR('Access Denied: Insufficient privileges', 16, 1);
            RETURN;
        END
        
        --  MLS
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
        
       
        INSERT INTO Attendance (StudentID, CourseID, Status, RecordedByUserID, ClassificationLevel)
        VALUES (@StudentID, @CourseID, @Status, @RequestingUserID, 3);
        
        DECLARE @AttendanceID INT = SCOPE_IDENTITY();
        
        
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@RequestingUserID, 'Record Attendance', 'Attendance', @AttendanceID);
        
        SELECT 'Success' AS Result, @AttendanceID AS AttendanceID;
    END TRY
    BEGIN CATCH
        INSERT INTO AuditLog (UserID, Action, Success, ErrorMessage)
        VALUES (@RequestingUserID, 'Record Attendance Failed', 0, ERROR_MESSAGE());
        
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

-- ============ Stored Procedures  ============

CREATE OR ALTER PROCEDURE sp_SubmitRoleRequest
    @UserID INT,
    @RequestedRole NVARCHAR(20),
    @Reason NVARCHAR(500),
    @Comments NVARCHAR(MAX) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        DECLARE @Username NVARCHAR(50);
        DECLARE @CurrentRole NVARCHAR(20);
        
        SELECT @Username = Username, @CurrentRole = Role 
        FROM Users 
        WHERE UserID = @UserID;
        
        IF @Username IS NULL
        BEGIN
            RAISERROR('User not found', 16, 1);
            RETURN;
        END
        
        
        IF @RequestedRole NOT IN ('Admin', 'Instructor', 'TA', 'Student')
        BEGIN
            RAISERROR('Invalid role requested', 16, 1);
            RETURN;
        END
        
        
        IF EXISTS (SELECT 1 FROM RoleRequests WHERE UserID = @UserID AND Status = 'Pending')
        BEGIN
            RAISERROR('You already have a pending role request', 16, 1);
            RETURN;
        END
        
        
        INSERT INTO RoleRequests (UserID, Username, CurrentRole, RequestedRole, Reason, Comments, Status)
        VALUES (@UserID, @Username, @CurrentRole, @RequestedRole, @Reason, @Comments, 'Pending');
        
        DECLARE @RequestID INT = SCOPE_IDENTITY();
        
        
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@UserID, 'Submit Role Request', 'RoleRequests', @RequestID);
        
        SELECT 'Success' AS Result, @RequestID AS RequestID;
    END TRY
    BEGIN CATCH
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE sp_ProcessRoleRequest
    @RequestID INT,
    @Action NVARCHAR(20), -- 'Approve' or 'Deny'
    @ProcessingAdminID INT,
    @AdminComments NVARCHAR(MAX) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        --  Admin
        DECLARE @AdminRole NVARCHAR(20);
        SELECT @AdminRole = Role FROM Users WHERE UserID = @ProcessingAdminID;
        
        IF @AdminRole != 'Admin'
        BEGIN
            RAISERROR('Only Admin can process role requests', 16, 1);
            RETURN;
        END
        
        
        DECLARE @UserID INT;
        DECLARE @RequestedRole NVARCHAR(20);
        
        SELECT @UserID = UserID, @RequestedRole = RequestedRole
        FROM RoleRequests
        WHERE RequestID = @RequestID AND Status = 'Pending';
        
        IF @UserID IS NULL
        BEGIN
            RAISERROR('Request not found or already processed', 16, 1);
            RETURN;
        END
        
        IF @Action = 'Approve'
        BEGIN
            --  ClearanceLevel 
            DECLARE @NewClearance INT;
            SELECT @NewClearance = CASE @RequestedRole
                WHEN 'Admin' THEN 4
                WHEN 'Instructor' THEN 3
                WHEN 'TA' THEN 2
                WHEN 'Student' THEN 1
                ELSE 1
            END;
            
            
            UPDATE Users
            SET Role = @RequestedRole, ClearanceLevel = @NewClearance
            WHERE UserID = @UserID;
            
            
            UPDATE RoleRequests
            SET Status = 'Approved',
                ProcessedDate = GETDATE(),
                ProcessedByAdminID = @ProcessingAdminID,
                AdminComments = @AdminComments
            WHERE RequestID = @RequestID;
            
            --  AuditLog
            INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
            VALUES (@ProcessingAdminID, 'Approve Role Request', 'RoleRequests', @RequestID);
            
            SELECT 'Success' AS Result, 'Request approved and user role updated' AS Message;
        END
        ELSE IF @Action = 'Deny'
        BEGIN
            
            UPDATE RoleRequests
            SET Status = 'Denied',
                ProcessedDate = GETDATE(),
                ProcessedByAdminID = @ProcessingAdminID,
                AdminComments = @AdminComments
            WHERE RequestID = @RequestID;
            
            --  AuditLog
            INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
            VALUES (@ProcessingAdminID, 'Deny Role Request', 'RoleRequests', @RequestID);
            
            SELECT 'Success' AS Result, 'Request denied' AS Message;
        END
        ELSE
        BEGIN
            RAISERROR('Invalid action. Use Approve or Deny', 16, 1);
            RETURN;
        END
    END TRY
    BEGIN CATCH
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

-- ============  CourseEnrollment  ============

CREATE OR ALTER PROCEDURE sp_EnrollStudentInCourse
    @StudentID INT,
    @CourseID INT,
    @RequestingUserID INT
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        
        DECLARE @RequesterRole NVARCHAR(20);
        SELECT @RequesterRole = Role FROM Users WHERE UserID = @RequestingUserID;
        
        IF @RequesterRole NOT IN ('Admin', 'Instructor')
        BEGIN
            RAISERROR('Access Denied: Only Admin and Instructors can enroll students', 16, 1);
            RETURN;
        END
        
        
        IF EXISTS (SELECT 1 FROM CourseEnrollment WHERE StudentID = @StudentID AND CourseID = @CourseID)
        BEGIN
            RAISERROR('Student already enrolled in this course', 16, 1);
            RETURN;
        END
        
        
        INSERT INTO CourseEnrollment (StudentID, CourseID)
        VALUES (@StudentID, @CourseID);
        
        DECLARE @EnrollmentID INT = SCOPE_IDENTITY();
        
        --  AuditLog
        INSERT INTO AuditLog (UserID, Action, TableAffected, RecordID)
        VALUES (@RequestingUserID, 'Enroll Student', 'CourseEnrollment', @EnrollmentID);
        
        SELECT 'Success' AS Result, @EnrollmentID AS EnrollmentID;
    END TRY
    BEGIN CATCH
        SELECT 'Error' AS Result, ERROR_MESSAGE() AS ErrorMessage;
    END CATCH
END
GO

PRINT 'Additional procedures created successfully.';
GO

-- ============ test ============

PRINT '';
PRINT 'To add test data, run the following commands:';
PRINT '1. Create a student user: EXEC sp_RegisterUser ''student1'', ''student123'', ''Student'', 1, NULL';
PRINT '2. Create an instructor user: EXEC sp_RegisterUser ''instructor1'', ''inst123'', ''Instructor'', 3, NULL';
PRINT '3. Create a TA user: EXEC sp_RegisterUser ''ta1'', ''ta123'', ''TA'', 2, NULL';
PRINT '4. Link instructor to Instructor table';
PRINT '5. Enroll student in course: EXEC sp_EnrollStudentInCourse 1, 1, 1';
GO