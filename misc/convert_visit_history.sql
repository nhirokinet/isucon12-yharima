
drop table if exists visited_user;

create table visited_user (
    player_id varchar(255) not null,
    tenant_id varchar(255) not null,
    competition_id varchar(255) not null,
    initial_data tinyint(1) not null default 0,
    primary key (player_id, tenant_id, competition_id)
)  ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4;

insert into visited_user (select player_id, visit_history.tenant_id, competition_id, 1 from visit_history left join competition on competition.id=visit_history.competition_id where (finished_at is not null and competition.finished_at >= visit_history.created_at) or finished_at is null group by player_id,visit_history.tenant_id,competition_id);
