--users table
CREATE TABLE users (
	id serial primary key,
	username text not null unique,
	password text not null,
	name text not null,
	email text not null
);

--task_lists table
CREATE TABLE task_lists (
	id serial primary key,
	list_date date not null,
	user_id integer not null,
	foreign key (user_id) references users(id)
);

-- tasks table
create table tasks (
	id serial primary key,
	task text not null,
	done boolean not null default '0',
	task_list_id integer not null,
	foreign key (task_list_id) references task_lists(id)
);