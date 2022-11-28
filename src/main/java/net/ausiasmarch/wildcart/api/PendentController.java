package net.ausiasmarch.wildcart.api;

import net.ausiasmarch.wildcart.entity.PendentEntity;
import net.ausiasmarch.wildcart.service.PendentService;
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
@RequestMapping("/pendent")
public class PendentController {

    @Autowired
    private PendentService oPendentService;

    @GetMapping("/{id}")
    public ResponseEntity<PendentEntity> get(@PathVariable Long id) {
        return new ResponseEntity<>(oPendentService.get(id), HttpStatus.OK);
    }

    @GetMapping("/count")
    public ResponseEntity<Long> count() {
        return new ResponseEntity<>(oPendentService.count(), HttpStatus.OK);
    }

    @PostMapping("/")
    public ResponseEntity<PendentEntity> create(PendentEntity oPendentEntity) {
        return new ResponseEntity<>(oPendentService.create(oPendentEntity), HttpStatus.OK);
    }

    @PutMapping("/")
    public ResponseEntity<Long> update(PendentEntity oPendentEntity) {
        return new ResponseEntity<>(oPendentService.update(oPendentEntity), HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Long> delete(@PathVariable Long id) {
        return new ResponseEntity<>(oPendentService.delete(id), HttpStatus.OK);
    }
}
