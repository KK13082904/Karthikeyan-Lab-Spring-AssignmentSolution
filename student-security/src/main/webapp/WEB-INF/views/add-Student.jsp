<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Add Customer</title>
<link
	href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
	rel="stylesheet">
<script
	src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</head>
<body>
	<div class="container">
		<div class="container-fluid p-5 bg-primary text-white text-left">
			<h1>Student Management</h1>
		</div>
		<p class="h4 mb-4">Student Details</p>
		<div >
			<form action="/StudentSecurity/student/save" method="post">
				<div class="mb-3 mt-3">
					<input
						type="text" name="name" placeholder="Enter the Name"
						value="${Student.name}" class="form-control mb-4 col-4"/>
				</div>
				<div class="mb-3 mt-3">
					<input
						type="text" name="department" placeholder="Enter the Department"
						value="${Student.department}" class="form-control mb-4 col-4"/>
				</div>
				<div class="mb-3 mt-3">
					<input
						type="text" name="country" placeholder="Enter the Country"
						value="${Student.country}" class="form-control mb-4 col-4"/>
				</div>
				<input type="hidden" name="stuId" value="${Student.stuId}" />
				<input type="submit" name="Submit" class="btn btn-primary"
					Value="Add Student" />&nbsp;<a
					href="/StudentSecurity/student/list" class="btn btn-secondary">Cancel</a>
			</form>
		</div>
	</div>

</body>
</html>