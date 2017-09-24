package vo.learn.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

    @RequestMapping(path = {"/", "/home"})
    public String home(){
        return "home.html";
    }

    @RequestMapping("/hello")
    public String hello(){
        return "hello.html";
    }

    @RequestMapping("/login")
    public String login(){
        return "login.html";
    }

}
