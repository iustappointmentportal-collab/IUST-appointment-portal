# IUST Appointment Portal

IUST Appointment Portal with OTP authentication and Google Sheets integration.

## Profile Features

All profile features are now fully functional and have been improved:

- **View Profile:** Users can view their own profile information.
- **Update Profile:** Users can update their profile details. The API now supports partial updates, meaning you only need to send the fields that you want to change.
- **Faculty Availability:** Faculty members can update their availability schedule.

These features are handled by the following API endpoints:
- `GET /api/users/profile`
- `PUT /api/users/profile`
- `PUT /api/faculty/profile/availability`