require('dotenv').config()
const express = require('express')
const app = express()
const path = require('path')
const materias = ['matematica', 'fisica', 'PWEB', 'quimica', 'FSOR', 'POO']

const bcrypt = require('bcrypt')
const login_nao_Necessario = ['/criar_conta', '/fazer_login', '/registro', '/login'] // fazer depois
const jwt = require('jsonwebtoken')
const parser = require('cookie-parser')
app.use(parser())

// token de sessao vai te id, cpf e permissao
// aluno vai poder ver suas proprias notas e faltas
// nota e falta sao entidades com chave estrangeira (ID)
// professor pode colocar nota e inserir falta.
// registro -> feito
// login -> qse feito

// CREATE TABLE usuarios (id BIGINT PRIMARY KEY AUTO_INCREMENT, cpf VARCHAR(11) NOT NULL UNIQUE, email VARCHAR(256) UNIQUE NOT NULL, nome VARCHAR(100) NOT NULL, senha VARCHAR(200) NOT NULL, permissao INT NOT NULL);
// CREATE TABLE notas (id BIGINT PRIMARY KEY AUTO_INCREMENT, id_aluno BIGINT, valor DECIMAL (3, 1) NOT NULL, materia VARCHAR(50) NOT NULL, tipo VARCHAR(9) NOT NULL, bimestre INT NOT NULL, FOREIGN KEY (id_aluno) REFERENCES usuarios(id));
// CREATE TABLE faltas (id BIGINT PRIMARY KEY AUTO_INCREMENT, id_aluno BIGINT, materia VARCHAR(50), dia DATE, FOREIGN KEY (id_aluno) REFERENCES usuarios(id));

// query p teste 
// fetch('/registro', {
//  method: 'POST',
//  body: JSON.stringify({
//      cpf: "12345678910",
//      email: "teste@gmail.com",
//      nome: "oi",
//      senha: "neymar",
//      permissao: 1
//  }),
//  headers: {'content-type':'application/json'}
// }).then(res => res.text()).then(obj => alert(obj));

// fetch('/login', {
//  method: 'POST',
//  body: JSON.stringify({
//      cpf: "12345678910",
//      senha: "neymar"
//  }),
//  headers: {'content-type':'application/json'}
// }).then(res => res.text()).then(obj => alert(obj));

// fetch('/notas/0?materia=matematica').then(res => res.text()).then(obj => alert(obj))
// fetch('/faltas/0?materia=matematica').then(res => res.text()).then(obj => alert(obj))

// fetch('/notas/1?materia=matematica').then(res => res.text()).then(obj => alert(obj))
// fetch('/faltas/1?materia=matematica').then(res => res.text()).then(obj => alert(obj))

// fetch('/faltas/1', {
//  method: 'POST',
//  body: JSON.stringify({
//      materia: "matematica",
//      dia: "2025-05-25"
//  }),
//  headers: {'content-type':'application/json'}
// }).then(res => res.text()).then(obj => alert(obj));

// await conn.query('INSERT INTO notas (id_aluno, valor, materia, tipo, bimestre) VALUES (?,?,?,?,?)', [req.params.id, req.body.nota, req.body.materia, req.body.tipo, req.body.bimestre])
// fetch('/notas/1', {
//  method: 'POST',
//  body: JSON.stringify({
//      materia: "matematica",
//      valor: 9.5,
//      tipo: "mensal",
//      bimestre: 1
//  }),
//  headers: {'content-type':'application/json'}
// }).then(res => res.text()).then(obj => alert(obj));

async function k() {
    const mysql = require('mysql2/promise')
    app.use(express.static(path.join(__dirname, 'public')))
    app.use(express.json())

    const con = await mysql.createConnection({
    user: process.env.user,
    password: process.env.password,
    port: 3306,
    database: process.env.database
    })

    let conn = await con

    app.use(async (req, res, next) => {
          if (login_nao_Necessario.includes(req.url)) {
            if (req.cookies.sessao) {
                return res.status(403).send('não autorizado')
            } else {
                return next()
            }
          } else {
            if (req.cookies.sessao) {
                let k = jwt.verify(req.cookies.sessao, process.env.chave)
                console.log(k.id, k.permissao)
                if (k.id && k.permissao) {
                    let conn = await con
                    let a = await conn.query(`SELECT * FROM usuarios WHERE id=? AND permissao=?`, [k.id, k.permissao]) // evitar fraude de permissao
                    if (a[0].length === 0) {
                        return res.status(401).send('não autorizado.')
                    } else {
                        return next()
                    }
                } else {
                    return res.status(401).send('não autorizado.')
                } 
            } else {
                return res.status(403).send('não autorizado.')
            }
          }

          
})
    //professor: cpf, senha, nome, id, email
    //aluno: cpf, senha, nome, id, email
    //esquece o de cima pq virou tudo a mesma entidade 'usuario'.
    //turma: qtd alunos, codigo
    //add nota, botar presença

    app.post('/registro', async (req, res) => {
        let b = await bcrypt.hash(req.body.senha,10)
        try {
        let a = await conn.query(`INSERT INTO usuarios (cpf, email, nome, senha, permissao) VALUES (?,?,?,?,?)`, [req.body.cpf, req.body.email, req.body.nome, b, req.body.permissao])
        res.cookie('sessao', jwt.sign({
                    id: a[0].insertId,
                    cpf: req.body.cpf,
                    permissao: req.body.permissao
                }, process.env.chave), {
                    expires: true,
                    maxAge: 1000*60*60*24,
                    httpOnly: true
                })
        return res.send('usuário criado com sucesso')
        // isso aq funciona pq no banco de dados vai ser cpf unique e email unique; portanto isso vai retornar um erro se os dados nao forem unicos. + id é BIG INT PRIMARY KEY AUTO_INCREMENT entao
        // nao precisa inserir ele (id)
        } catch(err) {
            console.log(err)
            return res.status(400).send('dados inválidos; em uso ou mal formatados.')
        }
    })

    app.post('/login', async (req, res) => {
        let a = await conn.query('SELECT senha, id, permissao FROM usuarios WHERE cpf=?', [req.body.cpf])
        if (a[0].length === 0) {
            return res.status(401).send('usuário inexistente')
        }
        let a2 = await bcrypt.compare(req.body.senha, a[0][0].senha)
            if (a2) {
                res.cookie('sessao', jwt.sign({
                    id: a[0][0].id,
                    cpf: req.body.cpf,
                    permissao: a[0][0].permissao
                }, process.env.chave), {
                    expires: true,
                    maxAge: 1000*60*60*24,
                    httpOnly: true
                })
                return res.send('usuário logado.')
            } else {
                return res.status(401).send('não autorizado.')
            }
    })

    app.get('/notas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (parseInt(req.params.id) === 0) { // significa que o cliente pediu a própria nota.
            if (req.query.materia) {
                if (!materias.includes(req.query.materia)) {
                    return res.status(401).send('matéria inválida.')
                }
                let a = await conn.query('SELECT * FROM notas WHERE id_aluno=? AND materia=?', [k.id, req.query.materia]) 
                    return res.send(a[0])
            } else {
                let b =  await conn.query('SELECT * FROM notas WHERE id_aluno=?', [k.id])
                    return res.send(b[0])
            }
        } else {
            if (k.permissao === 2) { // só professor pode ver nota de outras pessoas
                if (req.query.materia) {
                    let a = await conn.query('SELECT * FROM notas WHERE id_aluno=? AND materia=?', [req.params.id, req.query.materia]) 
                        return res.send(a[0])
                }  else {  
                    let b =  await conn.query('SELECT * FROM notas WHERE id_aluno=?', [k.id])
                        return res.send(b[0])
                }
            } else {
                return res.status(403).send('não autorizado.')
            }
            
        }
        
    })

    app.get('/faltas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (parseInt(req.params.id) === 0) { // significa que o cliente pediu as próprias faltas.
            if (req.query.materia) {
                if (!materias.includes(req.query.materia)) {
                        return res.status(401).send('matéria inválida.')
                }
                let a = await conn.query('SELECT * FROM faltas WHERE id_aluno=? AND materia=?', [k.id, req.query.materia]) 
                return res.send(a[0])
            } else {
                let b =  await conn.query('SELECT * FROM faltas WHERE id_aluno=?', [k.id])
                return res.send(b[0])
            }
        } else {
            if (k.permissao === 2) { // só professor pode ver falta de outras pessoas
                if (req.query.materia) {
                let a = await conn.query('SELECT * FROM faltas WHERE id_aluno=? AND materia=?', [req.params.id, req.query.materia]) 
                    return res.send(a[0])
                }  else {  
                let b =  await conn.query('SELECT * FROM faltas WHERE id_aluno=?', [k.id])
                    return res.send(b[0])
                }
            } else {
                return res.status(403).send('não autorizado.')
            }
            
        }
    })


    app.post('/faltas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (k.permissao === 2) {
            try {
                if (!materias.includes(req.body.materia)) {
                    return res.status(400).send('matéria inexistente.')
                }
                await conn.query('INSERT INTO faltas (id_aluno, materia, dia) VALUES (?,?,?)', [req.params.id, req.body.materia, req.body.dia])
                return res.send('falta inserida com sucesso!')
                // vai retornar erro se o aluno nao existir pq id_aluno é chave estrangeira que remete a coluna id da table alunos
            } catch(err) {
                return res.status(400).send('erro ao inserir falta; má formatação de dados.')
            }
             
        } else {
            return res.status(403).send('Não autorizado.')
        }
    })

    app.delete('/faltas/:id', async (req, res) => { // aqui é o id da falta.
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (k.permissao === 2) {
            try {
                await conn.query('DELETE FROM faltas WHERE id=?', [req.params.id])
                return res.send('falta apagada com sucesso!')
            } catch(err) {
                console.log(err)
                return res.status(500).send('erro interno do servidor.')
            }
 
        } else {
            return res.status(403).send('não autorizado.')
        }
    })

    app.delete('/notas/:id', async (req, res) => { // aqui é o id da nota.
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        console.log(k.permissao)
        if (k.permissao === 2) {
            try {
                await conn.query('DELETE FROM notas WHERE id=?', [req.params.id])
                return res.send('falta apagada com sucesso!')
            } catch(err) {
                console.log(err)
                return res.status(500).send('erro interno do servidor.')
            }
 
        } else {
            return res.status(403).send('não autorizado.')
        }
    })

    app.patch('/notas/:id', async (req, res) => { // nesse caso tbm é o id da nota.
        let k = jwt.verify(req.cookies.sessao)
        if (k.permissao === 2) {
            try {
                let a = req.body.mudancas // vai vir um array com as alteraçoes a serem feitas nessa nota.
                let a2 = req.body.valores // os valores de cada mudança.
                for (x in a) {
                    await conn.query(`UPDATE notas SET ${a[x]}=${a2[x]} WHERE id=?`, [parseInt(req.params.id)])
                }
                return res.send('alterações feitas!')
            } catch(err) {
                return res.status(500).send('erro interno do servidor.')
            }
        } else {
            return res.status(403).send('não autorizado.')
        }
    })

    app.patch('/faltas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao)
        if (k.permissao === 2) {
            try {
                let a = req.body.mudancas // vai vir um array com as alteraçoes a serem feitas nessa nota.
                let a2 = req.body.valores // os valores de cada mudança.
                for (x in a) {
                    await conn.query(`UPDATE faltas SET ${a[x]}=${a2[x]} WHERE id=?`, [parseInt(req.params.id)])
                }
                return res.send('alterações feitas!')
            } catch(err) {
                console.log(err)
                return res.status(500).send('erro interno do servidor.')
            }
        } else {
            return res.status(403).send('não autorizado.')
        }
    })

    app.post('/notas/:id', async (req, res) => {
        let k = jwt.verify(req.cookies.sessao, process.env.chave)
        if (k.permissao === 2) {
            try {
                if (!materias.includes(req.body.materia) || req.body.nota < 0 || req.body.nota > 10) {

                    return res.status(400).send('erro ao inserir nota; má formatação de dados.')
                }
                await conn.query('INSERT INTO notas (id_aluno, valor, materia, tipo, bimestre) VALUES (?,?,?,?,?)', [req.params.id, req.body.valor, req.body.materia, req.body.tipo, req.body.bimestre])
                // tipo é se a nota é mensal ou bimestral.
                // valor é só a nota mesmo (quanto tirou)
                // bimestre é qual bimestre.
                return res.send('nota inserida com sucesso!')
                // vai retornar erro se o aluno nao existir pq id_aluno é chave estrangeira que remete a coluna id da table alunos
            } catch(err) {
                console.log(err)
                return res.status(400).send('erro ao inserir nota; má formatação')
            }
             
        } else {
            return res.status(403).send('Não autorizado.')
        }
    })



    app.listen(8080, () => {
        console.log('servidor rodando em 8080')
    })


}

k()