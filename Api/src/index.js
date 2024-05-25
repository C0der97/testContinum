const express = require('express');
const { Sequelize } = require('sequelize');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;


const sequelize = new Sequelize('students', 'studentAdmin', '125&1333-', {
  host: 'mysql',
  dialect: 'mysql'
});


app.use(
  cors({
    origin: ["http://localhost:31459"],
    credentials: true,
  })
);

app.use(express.json());


const Student = sequelize.define('Students', {
  firstName: {
    type: Sequelize.STRING,
    allowNull: false
  },
  lastName: {
    type: Sequelize.STRING
  }
});



app.post('/students', async (req, res) => {
  const { firstName, lastName } = req.body;
  try {
    const student = await Student.create({ firstName, lastName });
    res.status(201).json(student);
  } catch (error) {
    console.error('Error al crear estudiante:', error);
    res.status(500).json({ error: 'Error al crear estudiante' });
  }
});

app.get('/students', async (req, res) => {
  try {
    const students = await Student.findAll();
    res.json(students);
  } catch (error) {
    console.error('Error al obtener estudiantes:', error);
    res.status(500).json({ error: 'Error al obtener estudiantes' });
  }
});

// Obtener un estudiante por ID
app.get('/students/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const student = await Student.findByPk(id);
    if (!student) {
      return res.status(404).json({ error: 'Estudiante no encontrado' });
    }
    res.json(student);
  } catch (error) {
    console.error('Error al obtener estudiante:', error);
    res.status(500).json({ error: 'Error al obtener estudiante' });
  }
});

app.put('/students/:id', async (req, res) => {
  const id = req.params.id;
  const { firstName, lastName } = req.body;
  try {
    const student = await Student.findByPk(id);
    if (!student) {
      return res.status(404).json({ error: 'Estudiante no encontrado' });
    }
    student.firstName = firstName;
    student.lastName = lastName;
    await student.save();
    res.json(student);
  } catch (error) {
    console.error('Error al actualizar estudiante:', error);
    res.status(500).json({ error: 'Error al actualizar estudiante' });
  }
});

app.delete('/students/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const student = await Student.findByPk(id);
    if (!student) {
      return res.status(404).json({ error: 'Estudiante no encontrado' });
    }
    await student.destroy();
    res.json({ message: 'Estudiante eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar estudiante:', error);
    res.status(500).json({ error: 'Error al eliminar estudiante' });
  }
});


app.get('/', async (req, res) => {
  sequelize.sync({ force: true })
  .then(() => {
    res.status(200).json({ status: 'ok' });
  })
  .catch((error) => {
    res.status(500).json({ status: 'error', detail: error.message });
  });

});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
