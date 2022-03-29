package com.greatlearning.student.service;

import java.util.List;

import javax.transaction.Transactional;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class StudentServiceImpl implements StudentService {

	private SessionFactory sessionFactory;

	private Session session;

	@Autowired
	StudentServiceImpl(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
		try {
			session = sessionFactory.getCurrentSession();
		} catch (HibernateException e) {
			session = sessionFactory.openSession();

		}
	}

	@Transactional
	public void save(Student theStu) {
		// TODO Auto-generated method stub

		Transaction txn = session.beginTransaction();

		session.saveOrUpdate(theStu);

		txn.commit();

	}

	@Transactional
	public Student findById(int stuId) {

		Student student = new Student();

		Transaction tx = session.beginTransaction();

		// find record with Id from the database table
		student = session.get(Student.class, stuId);

		tx.commit();

		return student;
	}

	@Transactional
	public List<Student> findAll() {
		Transaction tx = session.beginTransaction();

		// find all the records from the database table
		List<Student> student = session.createQuery("from Student").list();

		tx.commit();

		return student;
	}

	@Override
	public void deleteById(int stuId) {
		// TODO Auto-generated method stub

		Transaction txn = session.beginTransaction();

		Student student = session.get(Student.class, stuId);

		session.delete(student);

		txn.commit();

	}

}
