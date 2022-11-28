package net.ausiasmarch.wildcart.api;

import net.ausiasmarch.wildcart.entity.QuestionEntity;
import net.ausiasmarch.wildcart.service.QuestionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/question")
public class QuestionController {

    @Autowired
    private QuestionService oQuestionService;

    @GetMapping("/{id}")
    public ResponseEntity<QuestionEntity> get(@PathVariable Long id) {
        return new ResponseEntity<>(oQuestionService.get(id), HttpStatus.OK);
    }

    @GetMapping("/count")
    public ResponseEntity<Long> count() {
        return new ResponseEntity<>(oQuestionService.count(), HttpStatus.OK);
    }

    @PostMapping("/")
    public ResponseEntity<QuestionEntity> create(QuestionEntity oQuestionEntity) {
        return new ResponseEntity<>(oQuestionService.create(oQuestionEntity), HttpStatus.OK);
    }

    @PutMapping("/")
    public ResponseEntity<Long> update(QuestionEntity oQuestionEntity) {
        return new ResponseEntity<>(oQuestionService.update(oQuestionEntity), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Long> delete(@PathVariable Long id) {
        return new ResponseEntity<>(oQuestionService.delete(id), HttpStatus.OK);
    }
}
