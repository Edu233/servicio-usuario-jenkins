package com.usuario.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.usuario.config.JwtUtils;
import com.usuario.modelo.Usuario;
import com.usuario.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UsuarioService {
	private final UsuarioRepository usuarioRepository;
	private final PasswordEncoder passwordEncoder;
	
	
	//PARA GENERAR EL TOCKEN
	private final JwtUtils jwtUtils;
	
	public Usuario registrarUsuario(Usuario usuario) {
		if (usuarioRepository.existsByUsername(usuario.getUsername())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT,"❌ EL USUARIO '"+usuario.getUsername()+ "' YA EXISTE EN EL SISTEMA");
		}
		
		//ENCRIPTA EL PASSWORD
		usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
		
		return usuarioRepository.save(usuario);
	}
	
	// http://localhost:8080/api/v1/usuarios/login
	// AUTENTICACION USUARIO Y PASSWORD
	public String autenticarUsuario(String username, String password) {
		// 1. BUSCAR SI EL USUARIO EXISTE EN LA BD
		Usuario usuario= usuarioRepository.findByUsername(username)
				.orElseThrow(()-> new ResponseStatusException(
						HttpStatus.UNAUTHORIZED,"❌ USUARIO O CONTRASEÑA INCORRECTOS"));
		
		// 2. VERIFICAR SI LA CONTRASEÑA ENCRIPTADA COINCIDE
		if (!passwordEncoder.matches(password, usuario.getPassword())) {
			throw new ResponseStatusException(
					HttpStatus.UNAUTHORIZED,"❌ USUARIO O CONTRASEÑA INCORRECTOS");
		}
		// GENEREAR Y RETORNAR EL TOCKEN SI ES CORRECTO
		return jwtUtils.generarTocken(usuario.getUsername(), usuario.getPassword());
	}
	
	
}
