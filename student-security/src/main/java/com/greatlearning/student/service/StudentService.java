package com.greatlearning.student.service;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface StudentService {

	public void save(Student theStu);

	public Student findById(int stuId);

	public List<Student> findAll();

	public void deleteById(int stuId);
}
