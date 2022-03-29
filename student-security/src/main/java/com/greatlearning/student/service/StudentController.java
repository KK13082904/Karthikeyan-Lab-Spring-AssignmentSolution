package com.greatlearning.student.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.List;

@Controller

@RequestMapping("/student")
public class StudentController {

	@Autowired
	private StudentService studentService;

	@RequestMapping("/list")
	public String list(Model theModel) {

		// get Books from db
		List<Student> theStudent = studentService.findAll();

		// add to the spring model
		theModel.addAttribute("Student", theStudent);

		return "list-Student";
	}

	@RequestMapping("/showForm")
	public String showForm(Model theModel) {
		Student theStu = new Student();
		theStu.setStuId(0);
		theModel.addAttribute("Student", theStu);
		return "add-Student";
	}

	@PostMapping("/save")
	public String save(@RequestParam("stuId") int stuId, @RequestParam("name") String name,
			@RequestParam("department") String department, @RequestParam("country") String country) {

		System.out.println(stuId);
		Student theStu;
		if (stuId != 0) {
			theStu = studentService.findById(stuId);
			theStu.setName(name);
			theStu.setDepartment(department);
			theStu.setCountry(country);
		} else
			theStu = new Student(name, department, country);

		studentService.save(theStu);

		// use a redirect to prevent duplicate submissions
		return "redirect:/student/list";

	}

	@RequestMapping("/updateForm")
	public String updateForm(@RequestParam("stuId") int stuId, Model theModel) {

		Student theStu = studentService.findById(stuId);
		System.out.println(theStu);
		theModel.addAttribute("Student", theStu);
		return "add-Student";
	}

	@RequestMapping("/delete")
	public String delete(@RequestParam("stuId") int stuId) {
		studentService.deleteById(stuId);
		return "redirect:/student/list";
	}
	
	@RequestMapping("/403")
	public ModelAndView accesssDenied(Principal user) {

		ModelAndView model = new ModelAndView();

		if (user != null) {
			model.addObject("msg", "Hi " + user.getName() 
			+ ", you do not have permission to access this page!");
		} else {
			model.addObject("msg", 
			"You do not have permission to access this page!");
		}

		model.setViewName("403");
		return model;

	}

}
