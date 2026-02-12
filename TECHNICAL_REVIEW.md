KampongKoneck Technical Review Guide
====================================

Purpose
-------
This document explains how the Flask app is organized and how the main
features work. It is written for a technical review of the codebase.

Project Structure
-----------------
- __init__.py
  Main Flask application. Defines routes, session handling, and features.
- models.py
  SQLAlchemy models: User, Follow, Message, Notification, PasswordResetToken, Hobby.
- validators.py
  Server-side validation functions for each form.
- templates/
  Jinja2 HTML templates for pages and layouts.
- static/auth/css/style.css
  Global styling and layout rules.
- static/uploads/
  User-uploaded profile pictures (stored by generated filename).

Key Concepts
------------
- Authentication uses session storage (no Flask-Login).
- Validation happens on the server in validators.py.
- The UI uses Jinja2 templates with a shared base layout.
- Notifications are stored in the database and marked read on view.
- CSRF protection is enforced for all POST/PUT/PATCH/DELETE requests.

Application Flow
----------------
1) User visits "/"
   - Redirects to "/login".

2) Login
   - POST "/login": validate input, find user by username or email,
     verify password hash, store user_id in session.

3) Registration (5-step wizard)
   - "/register" uses session["register"] to store partial data.
   - Each step validates fields with validate_register_step().
   - On step 5, the user is created and logged in.

4) Profile Setup and Edit
   - "/profile/setup" and "/profile/edit" reuse the same template.
   - Profile picture is saved with a UUID filename to avoid collisions.

5) Explore / Search Users
   - "/search": filters by username or display name.
   - Follow and unfollow actions are POST requests.

6) Public Profile View
   - "/users/<username>": shows a public profile and followed-by mutuals.
   - Follow/unfollow and Challenge buttons are available for other users.

7) Messages
   - "/messages": placeholder page.
   - Direct message POST is allowed if privacy rules pass.

8) Notifications
   - "/notifications": reads and marks notifications as read.

Database Models (High Level)
----------------------------
- User
  Stores login, profile details, privacy, and profile picture.
  Passwords are stored as hashes.

- Follow
  Many-to-many relationship between users.
  follower_id -> followed_id.

- Message
  Stores sender_id, receiver_id, message text, timestamps.

- Notification
  Stores user_id, type, message, created_at, read_at.

- PasswordResetToken
  Stores hashed reset tokens and expiration.

- Hobby
  List of available interests; users can select multiple.

Important Helper Functions
--------------------------
- load_current_user()
  Reads session["user_id"] and sets g.current_user.

- inject_user()
  Injects current_user and notification_count into templates.

- save_profile_picture()
  Validates file extension, generates UUID filename, saves to static/uploads.

Security and Validation
-----------------------
- Passwords are hashed using Werkzeug.
- File uploads are restricted by extension and size.
- Most POST routes are protected by login_required().
- Form data is validated with explicit validator functions.
- CSRF tokens are required for all state-changing requests.

Password Hashing (Where + How)
------------------------------
Where in the code:
- `models.py` in `User.set_password()` and `User.check_password()`.
  - `__init__.py` in registration step 3, which stores a password hash in session.

How it works:
- `set_password()` uses `werkzeug.security.generate_password_hash()` which
  applies PBKDF2 with SHA-256 by default.
- The hash includes a salt and iteration count. The plain password is never
  stored, only the hash.
- `check_password()` uses `werkzeug.security.check_password_hash()` to compare
  the provided password against the stored hash.

Password Hashing Details
------------------------
- Where in code
  - `models.py`: `User.set_password()` uses `generate_password_hash()`.
  - `models.py`: `User.check_password()` uses `check_password_hash()`.
  - `__init__.py`: login, reset password, and change password call these helpers.

- How it works
  - Werkzeug hashes with PBKDF2 + SHA-256 by default and includes a random salt.
  - The stored hash includes the algorithm and salt; it is never reversible.
  - On login, the provided password is hashed the same way and compared.

Notifications
-------------
- Follow and unfollow actions create a Notification for the target user.
- Notifications are displayed in "/notifications" and marked as read.

Search Follow/Unfollow Behavior
-------------------------------
- Follow/unfollow from search uses a "next" field.
- The server reads "next" and redirects back to search.

Template Layout
---------------
- base.html renders a side navigation for logged-in pages.
- hide_nav=True hides the side nav for auth pages.
- Each page extends base.html and fills the content block.
- Mobile uses a collapsible sidebar with a menu button and overlay.

Technical Notes (Deeper Explanation)
------------------------------------
- Request lifecycle
  - Before each request, load_current_user() populates g.current_user.
  - inject_user() makes current_user and notification_count available
    to all templates for navigation and badges.

- Auth and session handling
  - Session stores user_id after login or registration.
  - login_required() enforces authentication for protected routes.
  - Logout clears the session completely.

- Registration wizard
  - Step data is stored in session["register"]["data"].
  - Each step validates only the fields for that step.
  - Password is stored as a hash in the session (never raw).

- Profile privacy and messaging
  - Messaging is allowed if profile is public or if both users follow each other.
  - Public profile page shows followed-by mutuals in the right panel.

- Follow/unfollow
  - Follow creates a Follow row and a Notification for the target user.
  - Unfollow removes the Follow row and creates an "unfollow" notification.
  - Search uses a "next" field so follow/unfollow returns to the search page.
  - Redirect targets are validated as safe internal paths.

- Password reset flow
  - Reset tokens are hashed in the database.
  - Token validity and expiration are checked server-side.

- File uploads
  - Only allowed image extensions are accepted.
  - File size is limited by Flask's MAX_CONTENT_LENGTH (413 handler).
  - Filenames are replaced with UUIDs to avoid collisions.
  - Avatar cropper sends a cropped image for profile photos.

- CSRF protection
  - A per-session token is injected into all forms.
  - The server validates the token for all state-changing requests.

Potential Technical Review Questions
------------------------------------
Architecture and Structure
1) Why was a single-file auth.py used instead of Blueprints?
2) How would you split routes/services if the codebase grows?
3) Why did you choose SQLite for this stage?

Authentication and Security
4) How do you ensure passwords are never stored in plain text?
5) How is session security handled (secret key, session fixation)?
6) How do you handle file upload security?
7) What is the threat model for the password reset flow?

Validation and Error Handling
8) What happens when validation fails on each register step?
9) How do you preserve valid inputs across steps?
10) How are form errors surfaced to the user?

Data Model and Relationships
11) Why use a Follow table vs. a boolean on User?
12) How do you compute mutual followers efficiently?
13) How would you index or optimize the Follow queries?

Privacy and Permissions
14) How is private messaging enforced?
15) What prevents a user from accessing another user's private data?
16) How are follower/following lists protected?

Notifications
17) When are notifications created and marked as read?
18) How would you extend notifications for other events?

UX and Usability
19) How do you ensure the UI is elderly-friendly?
20) Why is the registration flow split into steps?

Testing and Maintainability
21) What areas should be unit tested first?
22) How would you add integration tests for auth and follow flows?
23) What would you refactor to reduce duplication in profile setup/edit?

Quick File Map for Reviewers
----------------------------
- Routes and flow: __init__.py
- Database schema: models.py
- Validation rules: validators.py
- Search UI: templates/search.html
- Public profile UI: templates/profile_public.html
- Settings UI: templates/settings.html
- Core styling: static/auth/css/style.css
