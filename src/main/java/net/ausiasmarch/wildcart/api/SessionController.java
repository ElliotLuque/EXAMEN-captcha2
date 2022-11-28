/*
 * Copyright (c) 2021
 *
 * by Rafael Angel Aznar Aparici (rafaaznar at gmail dot com) & 2021 DAW students
 *
 * WILDCART: Free Open Source Shopping Site
 *
 * Sources at:                https://github.com/rafaelaznar/wildCartSBServer2021
 * Database at:               https://github.com/rafaelaznar/wildCartSBServer2021
 * POSTMAN API at:            https://github.com/rafaelaznar/wildCartSBServer2021
 * Client at:                 https://github.com/rafaelaznar/wildCartAngularClient2021
 *
 * WILDCART is distributed under the MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package net.ausiasmarch.wildcart.api;

import net.ausiasmarch.wildcart.bean.CaptchaBean;
import net.ausiasmarch.wildcart.bean.TokenBean;
import net.ausiasmarch.wildcart.bean.UsuarioBean;
import net.ausiasmarch.wildcart.entity.UsuarioEntity;
import net.ausiasmarch.wildcart.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/session")
public class SessionController {

    @Autowired
    AuthService oAuthService;

    @GetMapping("")
    public ResponseEntity<UsuarioEntity> check() {
        return new ResponseEntity<UsuarioEntity>(oAuthService.check(), HttpStatus.OK);
    }

    @GetMapping("/prelogin")
    public ResponseEntity<TokenBean> prelogin() {
        return new ResponseEntity<>(oAuthService.prelogin(), HttpStatus.OK);
    }

    @GetMapping("/loginc")
    public ResponseEntity<UsuarioEntity> loginc(@RequestBody CaptchaBean oCaptchaBean) {
        return new ResponseEntity<UsuarioEntity>(oAuthService.loginC(oCaptchaBean), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<UsuarioEntity> login(@org.springframework.web.bind.annotation.RequestBody UsuarioBean oUsuarioBean) {
        return new ResponseEntity<UsuarioEntity>(oAuthService.login(oUsuarioBean), HttpStatus.OK);
    }

//    @PostMapping(produces = "application/json", consumes = "application/json")
//    public ResponseEntity<UsuarioEntity> login(
//            @org.springframework.web.bind.annotation.RequestBody // Spring
//            @io.swagger.v3.oas.annotations.parameters.RequestBody // Swagger
//            @Valid // Bean validation to ensure if the incoming object is valid
//            final UsuarioBean oUsuarioBean ) //            @RequestBody(description = "login endpoint", required = true, content = @Content(schema = @Schema(implementation = UsuarioEntity.class))) UsuarioBean oUsuarioBean) ,
//    {
//        return new ResponseEntity<UsuarioEntity>(oAuthService.login(oUsuarioBean), HttpStatus.OK);
//    }
    @DeleteMapping("")
    public ResponseEntity<?> logout() {
        oAuthService.logout();
        return new ResponseEntity<>(null, HttpStatus.OK);
    }

}
