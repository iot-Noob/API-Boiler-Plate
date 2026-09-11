# App/repository/UserRepository.py - CLEANER VERSION (error handling fixed)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.orm import joinedload
from typing import Optional, List, Dict, Any, Tuple
import logging
from datetime import datetime, timezone

# Import ONLY SQLAlchemy model
from App.api.databases.MigrateTable import User as UserModel
from App.core.exceptions import (
    UserNotFoundError,
    DuplicateEmailError,
    AccountAlreadyDisabledError,
    AccountNotDisabledError,
    AccountAlreadyDeletedError,
    AccountNotDeletedError,
    DuplicateNameError
)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
logger = logging.getLogger(__name__)


class UserRepository:
    """Repository for user database operations - NO SCHEMA DEPENDENCIES

    Error-handling convention used throughout this file:
      - Lookup methods (get_by_*) do NOT catch exceptions. A DB failure
        propagates to the caller instead of being silently turned into
        "not found". Returning None from these methods means the row
        genuinely does not exist.
      - Write/mutate methods raise ValueError for expected business-logic
        failures (e.g. "user not found") and let unexpected exceptions
        propagate after rolling back the session. Callers (routes) are
        responsible for translating these into the right HTTP response.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # ========== BASIC CRUD ==========

    async def get_by_id(self, user_id: int) -> Optional[UserModel]:
        """Get user by ID. Returns None only if the user genuinely
        doesn't exist. DB errors propagate to the caller."""
        result = await self.session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_ids(self, user_ids: List[int]) -> List[UserModel]:
        """Get multiple users by their IDs."""
        if not user_ids:
            return []

        result = await self.session.execute(
            select(UserModel).where(UserModel.id.in_(user_ids))
        )
        return result.scalars().all()

    async def get_by_email(self, email: str) -> Optional[UserModel]:
        """Get user by email."""
        result = await self.session.execute(
            select(UserModel).where(UserModel.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[UserModel]:
        """Get user by name."""
        result = await self.session.execute(
            select(UserModel).where(UserModel.name == name)
        )
        return result.scalar_one_or_none()

    async def create(self, user_data: Dict[str, Any]) -> UserModel:
        """Create new user from dictionary.

        Raises:
            DuplicateEmailError: if email already exists.
            SQLAlchemyError: for any other DB failure (propagates).
        """
        try:
            user = UserModel(**user_data)
            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"Created new user: {user.email}")
            return user

        except IntegrityError as e:
            await self.session.rollback()
            msg = str(e.orig).lower()
            if "email" in msg and ("unique" in msg or "duplicate" in msg):
                raise DuplicateEmailError(f"Email '{user_data.get('email')}' already registered") from e
            if "name" in msg and ("unique" in msg or "duplicate" in msg):
                raise DuplicateNameError(f"Name '{user_data.get('name')}' already taken") from e
            # Unknown constraint — don't guess, re-raise typed
            logger.exception("IntegrityError during user create")
            raise

        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception("DB error during user create")
            raise

    async def update(self, user_id: int, update_data: Dict[str, Any]) -> UserModel:
        """Update user with dictionary.

        Raises:
            UserNotFoundError
            DuplicateEmailError
            SQLAlchemyError
        """
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        try:
            for field, value in update_data.items():
                if hasattr(user, field):
                    setattr(user, field, value)

            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"Updated user {user_id}")
            return user

        except IntegrityError as e:
            await self.session.rollback()
            msg = str(e.orig).lower()
            if "email" in msg:
                raise DuplicateEmailError("Email already in use") from e
            logger.exception(f"IntegrityError updating user {user_id}")
            raise

        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error updating user {user_id}")
            raise

    async def update_password_hash(self, user_id: int, password_hash: str) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        try:
            user.password_hash = password_hash
            await self.session.commit()
            logger.info(f"Updated password hash for user {user_id}")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error updating password for user {user_id}")
            raise

    # ========== ACCOUNT STATE ==========

    async def disable_account(self, user_id: int) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        if user.disabled:
            raise AccountAlreadyDisabledError(f"User {user_id} is already disabled")

        try:
            user.disabled = True
            await self.session.commit()
            logger.info(f"Soft deleted (disabled) user {user_id}")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error disabling user {user_id}")
            raise

    async def restore_disable(self, user_id: int) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        if not user.disabled:
            return False  # nothing to do — not an error

        try:
            user.disabled = False
            user.is_active = True
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"User {user_id} fully restored from disabled")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error restoring user {user_id}")
            raise

    async def full_restore(self, user_id: int) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")

        try:
            user.disabled = False
            user.is_active = True
            user.is_deleted = False
            user.deleted_at = None
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"User {user_id} fully restored")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error fully restoring user {user_id}")
            raise

    async def delete_account(self, user_id: int) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        if user.is_deleted:
            return False  # idempotent

        try:
            user.is_deleted = True
            user.disabled = True
            user.is_active = False
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"User {user_id} soft deleted at {user.deleted_at}")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error soft deleting user {user_id}")
            raise

    async def restore_deleted(self, user_id: int) -> bool:
        user = await self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        if not user.is_deleted:
            return False

        try:
            user.is_deleted = False
            user.deleted_at = None
            user.disabled = False
            user.is_active = True
            await self.session.commit()
            await self.session.refresh(user)
            logger.info(f"User {user_id} restored successfully")
            return True
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception(f"DB error restoring user {user_id}")
            raise

    # ========== QUERIES ==========

    async def get_user_role(self, user_id: int) -> Optional[str]:
        """Get user role by ID."""
        user = await self.get_by_id(user_id)
        return user.user_role if user else None

    async def is_user_active(self, user_id: int) -> bool:
        """Check if user is active and not disabled."""
        user = await self.get_by_id(user_id)
        return bool(user and user.is_active and not user.disabled)

    async def is_user_disabled(self, user_id: int) -> bool:
        """Check if user is disabled."""
        user = await self.get_by_id(user_id)
        return bool(user and user.disabled)

    async def search_users(
        self,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = True,
        search: Optional[str] = None
    ) -> List[UserModel]:
        """Search users with pagination."""
        query = select(UserModel)

        if active_only:
            query = query.where(
                and_(
                    UserModel.is_active == True,
                    UserModel.disabled == False
                )
            )

        if search:
            search_filter = UserModel.name.ilike(f"%{search}%")
            if '@' in search:  # Likely an email search
                search_filter = search_filter | UserModel.email.ilike(f"%{search}%")
            query = query.where(search_filter)

        query = query.offset(skip).limit(limit).order_by(UserModel.created_at.desc())

        result = await self.session.execute(query)
        return result.scalars().all()

    async def count_users(self, active_only: bool = True) -> int:
        """Count total users."""
        query = select(func.count()).select_from(UserModel)

        if active_only:
            query = query.where(
                and_(
                    UserModel.is_active == True,
                    UserModel.disabled == False
                )
            )

        result = await self.session.execute(query)
        return result.scalar() or 0

    async def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email."""
        user = await self.get_by_email(email)
        return user is not None

    async def get_with_profile(self, user_id: int) -> Optional[UserModel]:
        """Get user with related profile data (if you have profiles)."""
        result = await self.session.execute(
            select(UserModel)
            .options(joinedload(UserModel.profile))  # If you have relationship
            .where(UserModel.id == user_id)
        )
        return result.scalar_one_or_none()

    # ========== UTILITIES ==========

    def to_dict(self, user: UserModel, exclude: List[str] = None) -> Dict[str, Any]:
        """Convert SQLAlchemy model to dictionary (NO Pydantic dependency)."""
        if exclude is None:
            exclude = []

        result = {}
        for column in user.__table__.columns:
            col_name = column.name
            if col_name not in exclude:
                result[col_name] = getattr(user, col_name)

        return result

    def to_safe_dict(self, user: UserModel) -> Dict[str, Any]:
        """Convert to dictionary excluding sensitive fields."""
        exclude_fields = ['password_hash', 'secret_key', 'token']
        return self.to_dict(user, exclude=exclude_fields)

    async def bulk_create(self, users_data: List[Dict[str, Any]]) -> List[UserModel]:
        try:
            users = []
            for user_data in users_data:
                users.append(UserModel(**user_data))
                self.session.add(users[-1])
            await self.session.commit()
            for user in users:
                await self.session.refresh(user)
            logger.info(f"Created {len(users)} users")
            return users
        except IntegrityError as e:
            await self.session.rollback()
            logger.exception("IntegrityError in bulk_create")
            raise DuplicateEmailError("One or more emails already exist") from e
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception("DB error in bulk_create")
            raise


    async def bulk_update(self, user_updates: List[Tuple[int, Dict[str, Any]]]) -> int:
        try:
            updated_count = 0
            for user_id, update_data in user_updates:
                user = await self.get_by_id(user_id)
                if user:
                    for field, value in update_data.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
                    updated_count += 1
            await self.session.commit()
            logger.info(f"Bulk updated {updated_count} users")
            return updated_count
        except IntegrityError as e:
            await self.session.rollback()
            logger.exception("IntegrityError in bulk_update")
            raise DuplicateEmailError("One or more emails already exist") from e
        except SQLAlchemyError:
            await self.session.rollback()
            logger.exception("DB error in bulk_update")
            raise

    @classmethod
    async def create_admin_if_not_exists(
        cls,
        session: AsyncSession,
        email: str,
        password_hash: str,
        name: str = "System Administrator",
        role: str = "admin",
        permissions: Dict[str, bool] = None,
    ) -> UserModel:
        """Race-safe admin creation via PostgreSQL INSERT ... ON CONFLICT."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        try:
            stmt = (
                pg_insert(UserModel)
                .values(
                    name=name, email=email, password_hash=password_hash,
                    user_role=role, is_active=True, disabled=False,
                    is_deleted=False, permissions=permissions or {},
                )
                .on_conflict_do_nothing(index_elements=["email"])
                .returning(UserModel.id)
            )
            result = await session.execute(stmt)
            inserted = result.scalar_one_or_none()
            await session.commit()

            if inserted is not None:
                logger.info(f"New admin created: {email}")
                return await cls._get_by_id(session, inserted)

            # Row existed — lock and return
            result = await session.execute(
                select(UserModel).where(UserModel.email == email).with_for_update()
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                raise AdminCreationError(f"Admin row for {email} disappeared mid-upsert")
            if existing.user_role == "admin":
                logger.info(f"Admin already exists: {email}")
                await session.commit()
                return existing

            logger.info(f"Promoting user to admin: {email}")
            existing.user_role = "admin"
            await session.commit()
            await session.refresh(existing)
            return existing

        except SQLAlchemyError:
            await session.rollback()
            logger.exception("DB error during admin creation")
            raise


    @classmethod
    async def _get_by_id(cls, session: AsyncSession, user_id: int) -> UserModel | None:
        result = await session.execute(select(UserModel).where(UserModel.id == user_id))
        return result.scalar_one_or_none()

    # @classmethod
    # async def create_admin_if_not_exists(
    #     cls,
    #     session: AsyncSession,  # MUST pass session explicitly
    #     email: str,
    #     password_hash: str,
    #     name: str = "System Administrator",
    #     role: str = "admin",
    #     permissions: Dict[str, bool] = None,
    # ) -> UserModel:
    #     """
    #     Create admin user if it doesn't exist. Class method for use in
    #     migrations/startup scripts — session passed explicitly since
    #     there's no repository instance yet.

    #     Raises:
    #         ValueError: if creation/promotion fails.
    #     """
    #     try:
    #         result = await session.execute(
    #             select(UserModel).where(
    #                 or_(UserModel.email == email, UserModel.name == name)
    #             )
    #         )
    #         existing_user = result.scalar_one_or_none()

    #         if existing_user:
    #             if existing_user.user_role == "admin":
    #                 logger.info(f"Admin already exists: {email}")
    #                 return existing_user

    #             logger.info(f"Promoting user to admin: {email}")
    #             existing_user.user_role = "admin"

    #             await session.commit()
    #             await session.refresh(existing_user)
    #             logger.info(f"Promoted user to admin: {email}")
    #             return existing_user

    #         logger.info(f"Creating new admin: {email}")
    #         new_admin = UserModel(
    #             name=name,
    #             email=email,
    #             password_hash=password_hash,
    #             user_role=role,
    #             is_active=True,
    #             disabled=False,
    #             is_deleted=False,
    #             permissions=permissions or {}
    #         )
    #         session.add(new_admin)
    #         await session.commit()
    #         await session.refresh(new_admin)
    #         logger.info(f"New admin created: {email}")
    #         return new_admin

    #     except Exception as e:
    #         await session.rollback()
    #         logger.error(f"Error creating/promoting admin: {e}")
    #         raise ValueError(f"Failed to create/promote admin: {str(e)}")

    # ========== PERMISSIONS ==========

    async def set_permissions(self, user_id: int, permissions: Dict[str, bool]) -> UserModel:
        """
        Set permissions for a user (MERGE behavior):
        - If permission key exists, update its value
        - If permission key doesn't exist, add it
        - Other existing permissions remain unchanged

        Raises:
            ValueError: if user not found or update fails.
        """
        user = await self.get_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        try:
            permissions = permissions or {}

            if user.permissions is None:
                user.permissions = {}

            # MERGE existing permissions with the new ones
            user.permissions = {**user.permissions, **permissions}

            await self.session.commit()
            await self.session.refresh(user)

            return user

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to merge permissions for user {user_id}: {e}")
            raise ValueError(f"Failed to merge permissions for user {user_id}: {str(e)}")

    async def replace_all_permissions(self, user_id: int, permissions: Dict[str, bool]) -> UserModel:
        """
        Replace ALL permissions for a user with new ones (full overwrite).

        Raises:
            ValueError: if user not found or update fails.
        """
        user = await self.get_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        try:
            user.permissions = permissions or {}

            await self.session.commit()
            await self.session.refresh(user)

            return user

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to replace permissions for user {user_id}: {e}")
            raise ValueError(f"Failed to replace permissions for user {user_id}: {str(e)}")

    async def remove_permissions(self, user_id: int, permission_keys: List[str]) -> UserModel:
        """Remove specific permission keys from a user.

        Raises:
            ValueError: if user not found or update fails.
        """
        user = await self.get_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        try:
            permission_keys = permission_keys or []
            current_perms = dict(user.permissions or {})  # copy, don't mutate original

            removed_keys = []
            for key in permission_keys:
                if key in current_perms:
                    del current_perms[key]
                    removed_keys.append(key)

            user.permissions = current_perms  # reassignment -> flags column dirty

            await self.session.commit()
            await self.session.refresh(user)

            if removed_keys:
                logger.info(f"Removed permissions for user {user_id}: {removed_keys}")
            else:
                logger.info(f"No permissions removed for user {user_id}")

            return user

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to remove permissions for user {user_id}: {e}")
            raise ValueError(f"Failed to remove permissions for user {user_id}: {str(e)}")

    async def remove_all_permissions(self, user_id: int) -> UserModel:
        """Remove ALL permissions from a user.

        Raises:
            ValueError: if user not found or update fails.
        """
        user = await self.get_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        try:
            user.permissions = {}

            await self.session.commit()
            await self.session.refresh(user)

            logger.info(f"Removed ALL permissions for user {user_id}")

            return user

        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to remove ALL permissions for user {user_id}: {e}")
            raise ValueError(f"Failed to remove ALL permissions for user {user_id}: {str(e)}")

    async def get_user_permission_db(
        self,
        user_id: Optional[int] = None,
        skip: int = 0,
        limit: int = 100,
        include_user_info: bool = False
    ) -> Dict[str, Any]:
        """
        Get user permissions with pagination support.

        If user_id is provided, returns permissions for that specific user.
        Otherwise returns a paginated dict of all active users' permissions.

        Raises:
            ValueError: if user_id is provided but the user doesn't exist.
        """
        # ============================================================
        # CASE 1: Get permissions for specific user
        # ============================================================
        if user_id is not None:
            user = await self.get_by_id(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")

            if include_user_info:
                return {
                    "permissions": user.permissions or {},
                    "user_info": {
                        "id": user.id,
                        "email": user.email,
                        "name": user.name,
                        "role": user.user_role
                    }
                }
            else:
                return user.permissions or {}

        # ============================================================
        # CASE 2: Get permissions for ALL users (with pagination)
        # ============================================================
        count_query = select(func.count()).select_from(UserModel).where(
            and_(
                UserModel.is_active == True,
                UserModel.disabled == False,
                UserModel.is_deleted == False
            )
        )
        total_result = await self.session.execute(count_query)
        total_count = total_result.scalar() or 0

        query = select(UserModel).where(
            and_(
                UserModel.is_active == True,
                UserModel.disabled == False,
                UserModel.is_deleted == False
            )
        ).order_by(UserModel.id).offset(skip).limit(limit)

        result = await self.session.execute(query)
        users = result.scalars().all()

        users_dict = {}
        for user in users:
            if include_user_info:
                users_dict[str(user.id)] = {
                    "permissions": user.permissions or {},
                    "email": user.email,
                    "name": user.name,
                    "role": user.user_role
                }
            else:
                users_dict[str(user.id)] = user.permissions or {}

        next_skip = skip + limit
        has_next = next_skip < total_count

        return {
            "users": users_dict,
            "pagination": {
                "total": total_count,
                "skip": skip,
                "limit": limit,
                "has_next": has_next,
                "next": f"/api/v1/admin/users/permissions?skip={next_skip}&limit={limit}" if has_next else None
            }
        }