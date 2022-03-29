<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<link
	href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
	rel="stylesheet">
<script
	src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
<!-- <link herf="<c:url value="/resources/css/style.css"/> "> -->
<title>Student List</title>
</head>
<body>
	<!-- <img alt="Imgae" src="<c:url value="/student/resources/images/delete.png"/>"> -->
	<div class="container">
		<div class="container-fluid p-5 bg-primary text-white text-left">
			<h1>Student Management</h1>
		</div>
		<div>
		<table class="table table-striped">
			<thead class="thead-dark">
				<tr>&nbsp;</tr>
				<tr>
					<th></th>
					<th></th>
					<th></th>
					<th class="text-right"><a
						href="/StudentSecurity/student/showForm" class="btn btn-success">Add
							Student</a>
							&nbsp;
							<a href="/StudentSecurity/logout" 
					class="btn btn-primary btn-sm mb-3 mx-auto"> Logout </a> </th>
				</tr>

				<tr>
					<th>Name</th>
					<th>Department</th>
					<th>Country</th>
				</tr>
			</thead>

			<tbody>
				<c:forEach items="${Student}" var="tempStudent">
					<tr>
						<td><c:out value="${tempStudent.name}" /></td>
						<td><c:out value="${tempStudent.department}" /></td>
						<td><c:out value="${tempStudent.country}" /></td>
						<td><a
							href="/StudentSecurity/student/updateForm?stuId=${tempStudent.stuId}"
							class="btn btn-info">Update</a> &nbsp; <a
							href="/StudentSecurity/student/delete?stuId=${tempStudent.stuId}"
							onclick="if (!(confirm('Are you sure you want to delete this Student?'))) return false"
							class="btn btn-danger">Delete</a></td>
					</tr>
				</c:forEach>
			</tbody>
		</table>
		</div>
	</div>
</body>
</html>