class CreateVexAuthInfos < ActiveRecord::Migration[6.1]
  def change
    create_table :vex_auth_infos, if_not_exists: true do |t|
      t.bigint :vex_id
      t.integer :user_id
      t.string :email

      t.timestamps
    end
  end
end
